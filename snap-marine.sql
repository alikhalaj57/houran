-- ============================================================
-- ⚓ Snap Marine — راه‌اندازی دیتابیس + امنیت سمت سرور (RLS)
-- این فایل را یک‌بار در Supabase → SQL Editor اجرا کنید. اجرای دوباره بی‌خطر است.
-- مدل داده: یک جدول records (entity + data jsonb) برای همه ماژول‌ها.
-- رکورد متای کاربران: 00000000-0000-4000-8000-00000000aaaa (باید با اپ یکسان بماند)
-- ============================================================

create table if not exists public.records (
  id uuid primary key,
  entity text not null,
  data jsonb not null default '{}'::jsonb,
  updated_at timestamptz not null default now(),
  deleted boolean not null default false
);
create index if not exists records_entity_idx on public.records(entity);
create index if not exists records_updated_idx on public.records(updated_at);
create index if not exists records_del_upd_idx on public.records(deleted, updated_at);

-- ---------- توابع کمکی (SECURITY DEFINER) ----------
create or replace function public.app_email() returns text
language sql stable security definer set search_path=public as
$$ select lower(coalesce(auth.jwt()->>'email','')) $$;

create or replace function public.app_users_list() returns jsonb
language sql stable security definer set search_path=public as
$$ select coalesce((select data->'list' from records
   where id='00000000-0000-4000-8000-00000000aaaa' and not deleted),'[]'::jsonb) $$;

create or replace function public.app_role() returns text
language plpgsql stable security definer set search_path=public as $$
declare lst jsonb; r text;
begin
  if app_email()='' then return ''; end if;
  lst:=app_users_list();
  if jsonb_array_length(lst)=0 then return 'ادمین'; end if; -- نخستین کاربر = ادمین
  select x->>'role' into r from jsonb_array_elements(lst) x
   where lower(coalesce(x->>'email',''))=app_email() limit 1;
  return coalesce(r,'در انتظار تایید');
end $$;

create or replace function public.app_is_admin() returns boolean
language sql stable security definer set search_path=public as
$$ select app_role()='ادمین' $$;

create or replace function public.app_is_operator() returns boolean
language sql stable security definer set search_path=public as
$$ select app_role() in ('ادمین','اپراتور') $$;

create or replace function public.app_approved() returns boolean
language sql stable security definer set search_path=public as
$$ select app_email()<>'' and app_role() not in ('','در انتظار تایید') $$;

create or replace function public.app_is_meta(rid uuid) returns boolean
language sql immutable as
$$ select rid='00000000-0000-4000-8000-00000000aaaa' $$;

-- ---------- RLS ----------
alter table public.records enable row level security;
alter table public.records force row level security;

do $$ declare p record; begin
  for p in select policyname from pg_policies where schemaname='public' and tablename='records'
  loop execute format('drop policy if exists %I on public.records', p.policyname); end loop;
end $$;

-- خواندن: کاربر تاییدشده همه را می‌بیند؛ کاربر در انتظار فقط رکورد متای کاربران را (برای دانستن نقش خود)
create policy rec_select on public.records for select to authenticated using (
  app_approved() or app_is_meta(id)
);

-- درج: کاربر تاییدشده؛ متای کاربران فقط ادمین — مگر وقتی هنوز هیچ کاربری ثبت نشده (راه‌اندازی اولیه)
create policy rec_insert on public.records for insert to authenticated with check (
  (not app_is_meta(id) and app_approved())
  or (app_is_meta(id) and (app_is_admin() or jsonb_array_length(app_users_list())=0))
);

-- ویرایش: ادمین/اپراتور همه؛ سایر نقش‌ها فقط رکوردهای خودشان (_by = ایمیل)؛ متا فقط ادمین
create policy rec_update on public.records for update to authenticated using (
  (app_is_meta(id) and app_is_admin())
  or (not app_is_meta(id) and app_approved() and (app_is_operator() or lower(coalesce(data->>'_by',''))=app_email()))
) with check (
  (app_is_meta(id) and app_is_admin()) or (not app_is_meta(id) and app_approved())
);

-- حذف فیزیکی: فقط ادمین (اپ از حذف نرم deleted=true استفاده می‌کند)
create policy rec_delete on public.records for delete to authenticated using (app_is_admin());

-- ---------- Realtime ----------
do $$ begin
  begin alter publication supabase_realtime add table public.records; exception when duplicate_object then null; end;
end $$;
alter table public.records replica identity full;

-- ---------- فایل‌ها (اختیاری): باکت اسناد ----------
insert into storage.buckets (id,name,public) values ('documents','documents',false) on conflict do nothing;
do $$ begin
  drop policy if exists sm_read on storage.objects; drop policy if exists sm_write on storage.objects;
  create policy sm_read on storage.objects for select to authenticated using (bucket_id='documents' and app_approved());
  create policy sm_write on storage.objects for insert to authenticated with check (bucket_id='documents' and app_approved());
end $$;

select '⚓ Snap Marine آماده است ✅' as status,
  (select count(*) from pg_policies where tablename='records') as policies;
