-- FIT: base de datos para sincronizar la app (pegar entero en Supabase > SQL Editor > Run)
create extension if not exists pgcrypto with schema extensions;

create table if not exists public.fit_docs (
  id text primary key,
  body jsonb,
  updated_at timestamptz not null default now()
);
create table if not exists public.fit_secret (
  id int primary key default 1 check (id = 1),
  secret_hash text not null
);
alter table public.fit_docs enable row level security;
alter table public.fit_secret enable row level security;
revoke all on public.fit_docs, public.fit_secret from anon, authenticated;

create or replace function public.fit_check(p_secret text) returns boolean
language sql security definer set search_path = public as $$
  select exists (select 1 from fit_secret
    where secret_hash = encode(extensions.digest(p_secret, 'sha256'), 'hex'));
$$;
revoke execute on function public.fit_check(text) from public, anon, authenticated;

create or replace function public.fit_init(p_secret text) returns boolean
language plpgsql security definer set search_path = public as $$
begin
  if exists (select 1 from fit_secret) then return fit_check(p_secret); end if;
  if length(p_secret) < 24 then raise exception 'clave muy corta'; end if;
  insert into fit_secret (id, secret_hash) values (1, encode(extensions.digest(p_secret, 'sha256'), 'hex'));
  return true;
end $$;

create or replace function public.fit_pull(p_secret text, p_since timestamptz)
returns setof public.fit_docs
language plpgsql security definer set search_path = public as $$
begin
  if not fit_check(p_secret) then raise exception 'no autorizado'; end if;
  return query select * from fit_docs
    where updated_at > coalesce(p_since, 'epoch'::timestamptz) order by updated_at;
end $$;

create or replace function public.fit_push(p_secret text, p_id text, p_body jsonb)
returns timestamptz
language plpgsql security definer set search_path = public as $$
declare t timestamptz;
begin
  if not fit_check(p_secret) then raise exception 'no autorizado'; end if;
  insert into fit_docs (id, body, updated_at) values (p_id, p_body, clock_timestamp())
    on conflict (id) do update set body = excluded.body, updated_at = excluded.updated_at
    returning updated_at into t;
  return t;
end $$;

create or replace function public.fit_steps(p_secret text, p_date text default null, p_steps numeric default null)
returns text
language plpgsql security definer set search_path = public as $$
declare d date; m text[]; prev numeric; hoy date := (now() at time zone 'America/Argentina/San_Juan')::date;
begin
  if not fit_check(p_secret) then raise exception 'no autorizado'; end if;
  if p_steps is null then raise exception 'faltan los pasos'; end if;
  if lower(trim(coalesce(p_date,''))) = 'ayer' then d := hoy - 1;
  else
    m := regexp_match(coalesce(p_date,''), '(\d{4})-(\d{1,2})-(\d{1,2})');
    if m is not null then d := make_date(m[1]::int, m[2]::int, m[3]::int);
    else
      m := regexp_match(coalesce(p_date,''), '(\d{1,2})/(\d{1,2})/(\d{4})');
      if m is not null then d := make_date(m[3]::int, m[2]::int, m[1]::int); else d := hoy; end if;
    end if;
  end if;
  select (body->>'steps')::numeric into prev from fit_docs where id = 's-' || d::text;
  if prev is not null and round(p_steps) <= prev then
    return 'sin cambios ' || d::text || ': se mantienen ' || prev || ' pasos';
  end if;
  insert into fit_docs (id, body, updated_at)
    values ('s-' || d::text, jsonb_build_object('date', d::text, 'steps', round(p_steps)), clock_timestamp())
    on conflict (id) do update set body = excluded.body, updated_at = excluded.updated_at;
  return 'ok ' || d::text || ': ' || round(p_steps) || ' pasos';
end $$;

grant execute on function public.fit_init(text), public.fit_pull(text, timestamptz),
  public.fit_push(text, text, jsonb), public.fit_steps(text, text, numeric) to anon;
