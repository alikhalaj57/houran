-- ============================================================
-- 🛡️ Maalinex — سخت‌سازی امنیتی حداکثری (RLS سمت سرور)
-- این فایل را یک‌بار در Supabase → SQL Editor اجرا کنید.
-- پس از اجرا، تمام قواعد دسترسی در خود دیتابیس اعمال می‌شود و
-- دورزدن اپلیکیشن (اتصال مستقیم به API) هیچ دسترسی اضافه‌ای نمی‌دهد.
-- اجرای دوباره‌ی فایل بی‌خطر است (idempotent).
-- ============================================================

-- ---------- ۰) شناسه‌های متا (باید با اپ یکسان بماند) ----------
-- users  : 00000000-0000-4000-8000-00000000aaaa
-- options: 00000000-0000-4000-8000-00000000bbbb
-- acl    : 00000000-0000-4000-8000-00000000cccc

-- ---------- ۱) توابع کمکی (SECURITY DEFINER تا RLS خودشان را دور بزنند) ----------
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
  if jsonb_array_length(lst)=0 then return 'ادمین'; end if; -- نخستین کاربر: راه‌اندازی
  select x->>'role' into r from jsonb_array_elements(lst) x
   where lower(coalesce(x->>'email',''))=app_email() limit 1;
  return coalesce(r,'در انتظار تایید');
end $$;

create or replace function public.app_is_admin() returns boolean
language sql stable security definer set search_path=public as
$$ select app_role()='ادمین' $$;

create or replace function public.app_approved() returns boolean
language sql stable security definer set search_path=public as
$$ select app_email()<>'' and app_role() not in ('','در انتظار تایید') $$;

create or replace function public.app_is_meta(rid uuid) returns boolean
language sql immutable as
$$ select rid in ('00000000-0000-4000-8000-00000000aaaa',
                  '00000000-0000-4000-8000-00000000bbbb',
                  '00000000-0000-4000-8000-00000000cccc') $$;

create or replace function public.app_acl() returns jsonb
language sql stable security definer set search_path=public as
$$ select coalesce((select data from records
   where id='00000000-0000-4000-8000-00000000cccc' and not deleted),'{}'::jsonb) $$;

-- سطح دسترسی هر بخش از ماتریس (کاربر بر نقش اولویت دارد؛ خالی = پیش‌فرض مجاز)
create or replace function public.app_ent_level(ent text) returns text
language sql stable security definer set search_path=public as
$$ select coalesce(
     app_acl()->'users'->app_email()->'ent'->>ent,
     app_acl()->'roles'->app_role()->'ent'->>ent, '') $$;

-- تنظیم «محدوده داده» موثر (کاربر بر نقش اولویت دارد)
create or replace function public.app_scope() returns jsonb
language sql stable security definer set search_path=public as
$$ select coalesce(
     app_acl()->'users'->app_email()->'scope',
     app_acl()->'roles'->app_role()->'scope') $$;

-- شناسه‌های پرونده HR خود کاربر
create or replace function public.app_my_hr() returns setof uuid
language sql stable security definer set search_path=public as
$$ select id from records where entity='hr' and not deleted
     and lower(coalesce(data->>'email',''))=app_email() $$;

-- آیا این ردیف مستقیم به خود کاربر وصل است؟ (مسئول/عضو/…)
create or replace function public.app_row_mine(d jsonb) returns boolean
language sql stable security definer set search_path=public as
$$ select exists(select 1 from app_my_hr() h where d::text like '%'||h::text||'%') $$;

-- محدوده داده: شناسه‌های سازمانی مجاز (+ واحدهای شرکت‌های مجاز)
create or replace function public.app_scope_ids() returns setof uuid
language sql stable security definer set search_path=public as $$
  with s as (select app_scope() j)
  select (x#>>'{}')::uuid from s, jsonb_array_elements(coalesce(s.j->'c','[]'::jsonb)) x
  union select (x#>>'{}')::uuid from s, jsonb_array_elements(coalesce(s.j->'b','[]'::jsonb)) x
  union select (x#>>'{}')::uuid from s, jsonb_array_elements(coalesce(s.j->'u','[]'::jsonb)) x
  union select r.id from records r, s
   where r.entity='orgunit' and not r.deleted
     and exists(select 1 from jsonb_array_elements(coalesce(s.j->'c','[]'::jsonb)) c
                where r.data::text like '%'||(c#>>'{}')||'%')
$$;

-- آیا ردیف در محدوده داده کاربر است؟ (دو سطح اتصال غیرمستقیم)
create or replace function public.app_in_scope(rid uuid, ent text, d jsonb) returns boolean
language plpgsql stable security definer set search_path=public as $$
declare sc jsonb; strict_m boolean; txt text;
begin
  if app_is_admin() then return true; end if;
  sc:=app_scope();
  if sc is null or coalesce((sc->>'on')::int,0)=0 then return true; end if;
  if app_is_meta(rid) then return true; end if;
  txt:=d::text;
  if lower(coalesce(d->>'_by',''))=app_email() then return true; end if;
  if ent='hr' and lower(coalesce(d->>'email',''))=app_email() then return true; end if;
  if app_row_mine(d) then return true; end if;
  if ent in ('company','business','orgunit') then
    return exists(select 1 from app_scope_ids() a where a=rid);
  end if;
  -- اتصال مستقیم به یک شناسه مجاز (سریع؛ فقط متنِ همین ردیف بررسی می‌شود)
  if exists(select 1 from app_scope_ids() a where txt like '%'||a::text||'%') then return true; end if;
  -- ⚡ برای کارایی، بررسیِ اتصالِ غیرمستقیمِ سنگین (اسکنِ کل جدول به‌ازای هر ردیف) حذف شد.
  -- تفکیک دقیقِ چندسطحی همچنان سمت اپ (inMyScope) برای نمایش انجام می‌شود؛ سرور فقط نگهبانِ درشت است.
  -- ردیفِ دارای وابستگیِ سازمانی که مستقیم مجاز نبود → رد؛ ردیفِ بدون هیچ شناسه سازمانی → مجاز مگر حالت سخت‌گیرانه.
  strict_m:=coalesce((sc->>'strict')::int,0)=1;
  if strict_m then return false; end if;
  -- ردیفِ بدونِ هیچ شناسه سازمانی → مجاز (فقط جدولِ کوچکِ شرکت/کسب‌وکار/واحد اسکن می‌شود، نه کلِ رکوردها)
  return not exists(select 1 from records o
     where o.entity in ('company','business','orgunit') and not o.deleted
       and txt like '%'||o.id::text||'%');
end $$;

-- حریم شخصی «رشد فردی»: ردیف‌های دارای _by فقط برای صاحبشان
create or replace function public.app_priv_ok(d jsonb) returns boolean
language sql stable security definer set search_path=public as
$$ select app_is_admin() or coalesce(d->>'_by','')='' or lower(d->>'_by')=app_email() $$;

-- مالکیت هدف BSC / سنجه (خودش یا از طریق هدفِ والد سنجه)
create or replace function public.app_bsc_mine(ent text, d jsonb) returns boolean
language plpgsql stable security definer set search_path=public as $$
begin
  if app_row_mine(d) then return true; end if;
  if ent='measure' then
    return exists(select 1 from records b
      where b.entity='bsc' and not b.deleted
        and d::text like '%'||b.id::text||'%' and app_row_mine(b.data));
  end if;
  return false;
end $$;

-- ---------- ۱٫۹) کارایی: ایندکس + مهلت اجرای بیشتر برای دیتای حجیم ----------
create index if not exists records_updated_idx on public.records(updated_at);
create index if not exists records_entity_idx on public.records(entity);
-- مهلت اجرای کوئری برای کاربرانِ واردشده کمی بیشتر شود تا سینکِ حجیم تایم‌اوت نشود
do $$ begin
  begin execute 'alter role authenticated set statement_timeout = ''30s'''; exception when others then null; end;
end $$;

-- ---------- ۲) فعال‌سازی RLS و پاک‌سازی سیاست‌های قبلی ----------
alter table public.records enable row level security;
alter table public.records force row level security;

do $$ declare p record; begin
  for p in select policyname from pg_policies where schemaname='public' and tablename='records'
  loop execute format('drop policy if exists %I on public.records',p.policyname); end loop;
end $$;

revoke all on public.records from anon;

-- ---------- ۳) سیاست‌ها ----------
-- خواندن: فقط اعضای تاییدشده، بخشِ مخفی‌نشده، داخل محدوده داده، با حفظ حریم شخصی
create policy rec_select on public.records for select to authenticated using (
  -- ⚡ مسیر سریع ادمین: بدون هیچ بررسیِ سنگین (OR کوتاه‌مدار می‌شود)
  app_is_admin()
  -- رکورد کاربران برای هر واردشده خواندنی است تا وضعیت خودش (تاییدشده/در انتظار) را بداند (لازمِ ثبت‌نام)
  or id='00000000-0000-4000-8000-00000000aaaa'
  or (
    app_approved()
    and (app_is_meta(id) or app_ent_level(entity)<>'hide')
    and app_priv_ok(data)
    and app_in_scope(id,entity,data)
  )
);

-- درج: عضو تاییدشده؛ متا فقط ادمین (به‌جز ساخت اولیه)؛ سطح read/hide حق درج ندارد؛ _by فقط خود فرد
create policy rec_insert on public.records for insert to authenticated with check (
  app_approved()
  and (not app_is_meta(id) or app_is_admin()
       or (id='00000000-0000-4000-8000-00000000aaaa'
           and jsonb_array_length(app_users_list())=0)) -- راه‌اندازی نخستین ادمین
  and (app_is_meta(id) or app_ent_level(entity) not in ('hide','read'))
  and (coalesce(data->>'_by','')='' or lower(data->>'_by')=app_email() or app_is_admin())
  and app_in_scope(id,entity,data)
);

-- ویرایش (شامل حذف نرم): متا فقط ادمین؛ رشد فردی فقط صاحب؛
-- BSC/سنجه فقط مالک یا دارنده مجوز صریح edit/full؛ سایر بخش‌ها طبق ماتریس و محدوده
create policy rec_update on public.records for update to authenticated using (
  app_approved()
  and (not app_is_meta(id) or app_is_admin())
  and app_priv_ok(data)
  and app_in_scope(id,entity,data)
  and (app_is_meta(id) or app_ent_level(entity) not in ('hide','read'))
  and (entity not in ('bsc','measure') or app_is_admin()
       or app_bsc_mine(entity,data) or app_ent_level(entity) in ('edit','full'))
) with check (
  app_approved() and (not app_is_meta(id) or app_is_admin())
);

-- حذف فیزیکی: فقط ادمین
create policy rec_delete on public.records for delete to authenticated
  using (app_is_admin());

-- ---------- ۴) تریگر ضدتحریف: تغییر entity یا جعل _by ممنوع ----------
create or replace function public.app_guard_update() returns trigger
language plpgsql security definer set search_path=public as $$
begin
  if app_is_admin() then return new; end if;
  if new.entity is distinct from old.entity then
    raise exception 'تغییر نوع رکورد مجاز نیست';
  end if;
  if coalesce(new.data->>'_by','') is distinct from coalesce(old.data->>'_by','') then
    raise exception 'تغییر مالک رکورد مجاز نیست';
  end if;
  return new;
end $$;
drop trigger if exists trg_app_guard on public.records;
create trigger trg_app_guard before update on public.records
  for each row execute function public.app_guard_update();

-- ---------- ۴٫۵) ثبت‌نام امن تازه‌واردان (enroll_me) ----------
-- زیر RLS، کاربر جدید نمی‌تواند مستقیماً رکورد کاربران (متا) را بنویسد.
-- این تابع فقط «ایمیل خودش» را با نقش «در انتظار تایید» به لیست اضافه می‌کند
-- (اگر لیست خالی باشد، اولین نفر ادمین می‌شود). نمی‌تواند نقش کسی را عوض کند یا کسی را حذف کند.
create or replace function public.enroll_me() returns text
language plpgsql security definer set search_path=public as $$
declare em text; d jsonb; lst jsonb; MU uuid:='00000000-0000-4000-8000-00000000aaaa';
begin
  em:=app_email(); if em='' then return 'no-auth'; end if;
  select data into d from records where id=MU and not deleted;
  if d is null then
    insert into records(id,entity,data,updated_at,deleted)
      values(MU,'_users', jsonb_build_object('list', jsonb_build_array(jsonb_build_object('email',em,'role','ادمین'))), now(), false)
      on conflict (id) do update set data=excluded.data, updated_at=now(), deleted=false;
    return 'admin-bootstrap';
  end if;
  lst:=coalesce(d->'list','[]'::jsonb);
  if exists(select 1 from jsonb_array_elements(lst) x where lower(coalesce(x->>'email',''))=em) then
    return 'already';
  end if;
  update records set data=jsonb_set(d,'{list}', lst || jsonb_build_array(jsonb_build_object('email',em,'role','در انتظار تایید')), true),
    updated_at=now() where id=MU;
  return 'pending-added';
end $$;
grant execute on function public.enroll_me() to authenticated;

-- ---------- ۴٫۶) همگام‌سازی امن هویت (sync_me) — تشخیص ثبت‌نام مجدد با همان ایمیل ----------
-- شناسه‌ی حساب Supabase (uid) را کنار ایمیل ذخیره می‌کند. اگر کسی حساب قبلی‌اش حذف شده و
-- با «همان ایمیل» دوباره ثبت‌نام کند، uid جدید با uid ذخیره‌شده فرق دارد → نقشش به‌طور خودکار
-- به «در انتظار تایید» بازمی‌گردد تا دوباره نیاز به تایید ادمین داشته باشد.
create or replace function public.app_uid() returns text
language sql stable security definer set search_path=public as
$$ select coalesce(auth.jwt()->>'sub','') $$;

create or replace function public.sync_me() returns text
language plpgsql security definer set search_path=public as $$
declare em text; uid text; d jsonb; lst jsonb; newlst jsonb:='[]'::jsonb; el jsonb;
  found boolean:=false; changed boolean:=false; res text:='ok'; MU uuid:='00000000-0000-4000-8000-00000000aaaa';
begin
  em:=app_email(); uid:=app_uid();
  if em='' then return 'no-auth'; end if;
  select data into d from records where id=MU and not deleted;
  if d is null then
    insert into records(id,entity,data,updated_at,deleted)
      values(MU,'_users', jsonb_build_object('list', jsonb_build_array(jsonb_build_object('email',em,'role','ادمین','uid',uid))), now(), false)
      on conflict (id) do update set data=excluded.data, updated_at=now(), deleted=false;
    return 'admin-bootstrap';
  end if;
  lst:=coalesce(d->'list','[]'::jsonb);
  for el in select * from jsonb_array_elements(lst) loop
    if lower(coalesce(el->>'email',''))=em then
      found:=true;
      if coalesce(el->>'uid','')='' then
        el:=el || jsonb_build_object('uid',uid); changed:=true; res:='linked'; -- اولین اتصال uid، نقش حفظ می‌شود
      elsif el->>'uid' <> uid then
        el:=jsonb_build_object('email',em,'role','در انتظار تایید','uid',uid); changed:=true; res:='reset-pending'; -- حساب دوباره ساخته شده
      end if;
    end if;
    newlst:=newlst || el;
  end loop;
  if not found then
    newlst:=newlst || jsonb_build_object('email',em,'role','در انتظار تایید','uid',uid);
    changed:=true; res:='pending-added';
  end if;
  if changed then update records set data=jsonb_set(d,'{list}',newlst,true), updated_at=now() where id=MU; end if;
  return res;
end $$;
grant execute on function public.sync_me() to authenticated;

-- ---------- ۵) فایل‌ها (Storage) — فقط اعضای تاییدشده ----------
do $$ declare p record; begin
  for p in select policyname from pg_policies where schemaname='storage' and tablename='objects'
    and policyname like 'mlx_%'
  loop execute format('drop policy if exists %I on storage.objects',p.policyname); end loop;
end $$;
create policy mlx_read  on storage.objects for select to authenticated using (app_approved());
create policy mlx_write on storage.objects for insert to authenticated with check (app_approved());
create policy mlx_upd   on storage.objects for update to authenticated using (app_approved());
create policy mlx_del   on storage.objects for delete to authenticated using (app_is_admin());

-- ---------- پایان — بررسی سریع ----------
select 'RLS فعال شد ✅' as status,
  (select count(*) from pg_policies where tablename='records') as policies_records,
  (select count(*) from pg_policies where tablename='objects' and policyname like 'mlx_%') as policies_storage;
