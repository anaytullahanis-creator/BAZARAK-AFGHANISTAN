-- بازارک: schema پایه برای Supabase/PostgreSQL
-- در Supabase SQL Editor اجرا شود. پیش از راه‌اندازی واقعی، سیاست‌ها را با تست‌های امنیتی بررسی کنید.
create extension if not exists pgcrypto;

create type public.product_category as enum ('electronics','home','clothing','food','industrial','other');
create type public.product_status as enum ('pending','approved','rejected','archived');
create type public.order_status as enum ('new','accepted','processing','shipped','completed','cancelled');

create table public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  display_name text check (char_length(display_name) <= 120),
  created_at timestamptz not null default now()
);

create table public.companies (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null unique references auth.users(id) on delete cascade,
  name text not null check (char_length(trim(name)) between 2 and 120),
  country text not null check (char_length(trim(country)) between 2 and 80),
  city text check (char_length(city) <= 80),
  phone text check (char_length(phone) <= 40),
  whatsapp text check (char_length(whatsapp) <= 40),
  description text check (char_length(description) <= 1000),
  is_verified boolean not null default false,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table public.products (
  id uuid primary key default gen_random_uuid(),
  company_id uuid not null references public.companies(id) on delete cascade,
  name text not null check (char_length(trim(name)) between 2 and 160),
  category public.product_category not null default 'other',
  price numeric(12,2) not null check (price >= 0),
  currency char(3) not null default 'USD' check (currency in ('USD','AFN','EUR','PKR')),
  stock integer not null default 0 check (stock >= 0),
  description text not null check (char_length(description) between 1 and 2000),
  image_url text check (image_url is null or (char_length(image_url) <= 1000 and image_url like 'https://%')),
  status public.product_status not null default 'pending',
  is_active boolean not null default true,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create index products_public_catalog_idx on public.products(status,is_active,created_at desc);
create index products_company_idx on public.products(company_id);

create table public.orders (
  id uuid primary key default gen_random_uuid(),
  buyer_id uuid not null references auth.users(id) on delete restrict,
  status public.order_status not null default 'new',
  currency char(3) not null default 'USD' check (currency in ('USD','AFN','EUR','PKR')),
  buyer_message text check (char_length(buyer_message) <= 1000),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create index orders_buyer_idx on public.orders(buyer_id,created_at desc);

create table public.order_items (
  id uuid primary key default gen_random_uuid(),
  order_id uuid not null references public.orders(id) on delete cascade,
  product_id uuid references public.products(id) on delete set null,
  product_name text not null check (char_length(product_name) <= 160),
  company_name text not null check (char_length(company_name) <= 120),
  quantity integer not null check (quantity between 1 and 1000000),
  unit_price numeric(12,2) not null check (unit_price >= 0),
  created_at timestamptz not null default now()
);
create index order_items_order_idx on public.order_items(order_id);

-- Updated timestamp helper
create or replace function public.set_updated_at()
returns trigger language plpgsql as $$
begin new.updated_at = now(); return new; end; $$;
create trigger companies_updated_at before update on public.companies for each row execute function public.set_updated_at();
create trigger products_updated_at before update on public.products for each row execute function public.set_updated_at();
create trigger orders_updated_at before update on public.orders for each row execute function public.set_updated_at();

-- Create a profile on sign-up
create or replace function public.handle_new_user()
returns trigger language plpgsql security definer set search_path = '' as $$
begin
  insert into public.profiles (id, display_name)
  values (new.id, coalesce(new.raw_user_meta_data ->> 'display_name',''))
  on conflict (id) do nothing;
  return new;
end; $$;
create trigger on_auth_user_created after insert on auth.users for each row execute procedure public.handle_new_user();

alter table public.profiles enable row level security;
alter table public.companies enable row level security;
alter table public.products enable row level security;
alter table public.orders enable row level security;
alter table public.order_items enable row level security;

-- Profiles: user can see/update only own profile
create policy "profile select own" on public.profiles for select to authenticated using (id = (select auth.uid()));
create policy "profile update own" on public.profiles for update to authenticated using (id = (select auth.uid())) with check (id = (select auth.uid()));

-- Company details are public only when verified; owner can read own company and create/update own company.
create policy "verified companies public read" on public.companies for select to anon, authenticated using (is_verified = true or owner_id = (select auth.uid()));
create policy "company owner insert" on public.companies for insert to authenticated with check (owner_id = (select auth.uid()) and is_verified = false);
create policy "company owner update" on public.companies for update to authenticated using (owner_id = (select auth.uid())) with check (owner_id = (select auth.uid()) and is_verified = false);

-- Product catalog is public only for approved, active items; owners can see their own pending/rejected items.
create policy "public approved product read" on public.products for select to anon, authenticated using (
  (status = 'approved' and is_active = true)
  or exists (select 1 from public.companies c where c.id = company_id and c.owner_id = (select auth.uid()))
);
create policy "verified company owner insert product" on public.products for insert to authenticated with check (
  status = 'pending' and is_active = true and exists (
    select 1 from public.companies c where c.id = company_id and c.owner_id = (select auth.uid()) and c.is_verified = true
  )
);
create policy "owner update own pending product" on public.products for update to authenticated using (
  exists (select 1 from public.companies c where c.id = company_id and c.owner_id = (select auth.uid())
) ) with check (
  status in ('pending','archived') and exists (
    select 1 from public.companies c where c.id = company_id and c.owner_id = (select auth.uid()) and c.is_verified = true
  )
);
create policy "owner delete own product" on public.products for delete to authenticated using (
  exists (select 1 from public.companies c where c.id = company_id and c.owner_id = (select auth.uid()))
);

-- Orders: buyers can see/create their own orders. Sellers can read orders containing their own products.
create policy "buyer read own order" on public.orders for select to authenticated using (buyer_id = (select auth.uid()));
create policy "buyer cancel new order" on public.orders for update to authenticated using (buyer_id = (select auth.uid()) and status = 'new') with check (buyer_id = (select auth.uid()) and status in ('new','cancelled'));

-- Items: buyer can create item only on own order and only for an approved product.
create policy "buyer read own order items" on public.order_items for select to authenticated using (
  exists (select 1 from public.orders o where o.id = order_id and o.buyer_id = (select auth.uid()))
);
-- No direct client insert/update/delete policies for order_items; order creation must use the trusted RPC below.

-- Atomic request creation: price is read from the database, not trusted from browser input.
-- This creates a request only; it does not charge money or reserve/decrement stock.
create or replace function public.create_order_request(
  p_product_id uuid,
  p_quantity integer,
  p_buyer_message text default null
) returns uuid
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_user_id uuid := auth.uid();
  v_product public.products%rowtype;
  v_company_name text;
  v_order_id uuid;
begin
  if v_user_id is null then raise exception 'authentication_required'; end if;
  if p_quantity is null or p_quantity < 1 or p_quantity > 1000000 then raise exception 'invalid_quantity'; end if;
  if p_buyer_message is not null and char_length(p_buyer_message) > 1000 then raise exception 'message_too_long'; end if;

  select p.* into v_product
  from public.products p
  where p.id = p_product_id and p.status = 'approved' and p.is_active = true
  for update;
  if not found then raise exception 'product_unavailable'; end if;
  if v_product.stock < p_quantity then raise exception 'insufficient_stock'; end if;

  select c.name into v_company_name
  from public.companies c
  where c.id = v_product.company_id and c.is_verified = true;
  if v_company_name is null then raise exception 'seller_unavailable'; end if;

  insert into public.orders (buyer_id, status, currency, buyer_message)
  values (v_user_id, 'new', v_product.currency, nullif(trim(p_buyer_message),''))
  returning id into v_order_id;

  insert into public.order_items (order_id, product_id, product_name, company_name, quantity, unit_price)
  values (v_order_id, v_product.id, v_product.name, v_company_name, p_quantity, v_product.price);

  return v_order_id;
end;
$$;
revoke all on function public.create_order_request(uuid, integer, text) from public;
grant execute on function public.create_order_request(uuid, integer, text) to authenticated;

-- IMPORTANT ADMIN NOTE:
-- Do not let users set is_verified=true or products.status='approved' from the browser.
-- Perform approval with Supabase Dashboard / trusted server using service_role key stored server-side only.
-- Production order creation should be moved to a database function/API that atomically validates stock and snapshots prices.
