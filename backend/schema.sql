-- Agenda compartida: apply only to its independent Supabase project.
-- Add authorized members separately; no sample clients or events.
create table public.agenda_members (
  email text primary key check (email = lower(email)),
  name text not null check (char_length(name) between 1 and 80),
  theme text not null check (theme in ('qiyana','steve')),
  enabled boolean not null default true
);
alter table public.agenda_members enable row level security;
revoke all on public.agenda_members from anon, authenticated;
grant select on public.agenda_members to authenticated;
create policy member_reads_own_access on public.agenda_members
  for select to authenticated
  using (email = lower((select auth.jwt()->>'email')) and enabled);

create function public.agenda_is_member()
returns boolean language sql stable security invoker
set search_path = ''
as $$
  select auth.uid() is not null and exists (
    select 1 from public.agenda_members
    where email = lower(auth.jwt()->>'email') and enabled
  );
$$;
revoke all on function public.agenda_is_member() from public;
grant execute on function public.agenda_is_member() to authenticated;

create table public.agenda_clients (
  id uuid primary key default gen_random_uuid(),
  name text not null check (char_length(trim(name)) between 1 and 100),
  phone text not null default '' check (char_length(phone) <= 40),
  notes text not null default '' check (char_length(notes) <= 1000),
  created_by uuid not null default auth.uid() references auth.users(id),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create table public.agenda_events (
  id uuid primary key default gen_random_uuid(),
  client uuid not null references public.agenda_clients(id) on delete restrict,
  title text not null check (char_length(trim(title)) between 1 and 120),
  date date not null,
  time time not null,
  type text not null check (type in ('Pedido','Entrega','Visita')),
  owner text not null check (char_length(owner) between 1 and 80),
  notes text not null default '' check (char_length(notes) <= 1000),
  done boolean not null default false,
  created_by uuid not null default auth.uid() references auth.users(id),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create index agenda_events_date_idx on public.agenda_events(date,time);
create index agenda_events_client_idx on public.agenda_events(client);
create table public.agenda_preferences (
  user_id uuid primary key default auth.uid() references auth.users(id) on delete cascade,
  name text not null check (char_length(trim(name)) between 1 and 40),
  title text not null check (char_length(title) <= 80),
  color text not null check (color ~ '^#[0-9a-fA-F]{6}$'),
  light boolean not null default false,
  characters boolean not null default true,
  updated_at timestamptz not null default now()
);
create function public.agenda_touch_updated_at()
returns trigger language plpgsql security invoker set search_path = '' as $$
begin new.updated_at = now(); return new; end;
$$;
revoke all on function public.agenda_touch_updated_at() from public;
create trigger agenda_clients_touch before update on public.agenda_clients for each row execute function public.agenda_touch_updated_at();
create trigger agenda_events_touch before update on public.agenda_events for each row execute function public.agenda_touch_updated_at();
create trigger agenda_preferences_touch before update on public.agenda_preferences for each row execute function public.agenda_touch_updated_at();

alter table public.agenda_clients enable row level security;
alter table public.agenda_events enable row level security;
alter table public.agenda_preferences enable row level security;
revoke all on public.agenda_clients, public.agenda_events, public.agenda_preferences from anon, authenticated;
grant select, insert, update, delete on public.agenda_clients, public.agenda_events to authenticated;
grant select, insert, update on public.agenda_preferences to authenticated;
create policy team_clients_select on public.agenda_clients for select to authenticated using ((select public.agenda_is_member()));
create policy team_clients_insert on public.agenda_clients for insert to authenticated with check ((select public.agenda_is_member()) and created_by = (select auth.uid()));
create policy team_clients_update on public.agenda_clients for update to authenticated using ((select public.agenda_is_member())) with check ((select public.agenda_is_member()));
create policy team_clients_delete on public.agenda_clients for delete to authenticated using ((select public.agenda_is_member()));
create policy team_events_select on public.agenda_events for select to authenticated using ((select public.agenda_is_member()));
create policy team_events_insert on public.agenda_events for insert to authenticated with check ((select public.agenda_is_member()) and created_by = (select auth.uid()));
create policy team_events_update on public.agenda_events for update to authenticated using ((select public.agenda_is_member())) with check ((select public.agenda_is_member()));
create policy team_events_delete on public.agenda_events for delete to authenticated using ((select public.agenda_is_member()));
create policy own_preferences_select on public.agenda_preferences for select to authenticated using (user_id = (select auth.uid()) and (select public.agenda_is_member()));
create policy own_preferences_insert on public.agenda_preferences for insert to authenticated with check (user_id = (select auth.uid()) and (select public.agenda_is_member()));
create policy own_preferences_update on public.agenda_preferences for update to authenticated using (user_id = (select auth.uid()) and (select public.agenda_is_member())) with check (user_id = (select auth.uid()) and (select public.agenda_is_member()));
