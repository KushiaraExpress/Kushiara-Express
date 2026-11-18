# কুশিয়ারা এক্সপ্রেস — প্রোডাকশন ডিপ্লয়মেন্ট ও কনফিগারেশন গাইড

এই নথিতে GitHub, Supabase এবং Netlify ব্যবহার করে **কুশিয়ারা এক্সপ্রেস (KUSHIARA EXPRESS)** প্রোডাকশনে লাইভ করার সম্পূর্ণ ধাপসমূহ দেওয়া হয়েছে।

---

## ১. প্রজেক্ট আর্কিটেকচার ও ভার্সনিং নিয়ম

- **সংস্করণ নীতি**: প্রতিটি আপডেট কেবল কোড পরিবর্তন করে; প্রোডাকশন ডাটাবেজের প্রকাশিত সংবাদ, সেটিংস, বিজ্ঞাপন বা ক্যাটাগরি কখনোই মুছে ফেলা হয় না।
- **ডাটাবেজ মাইগ্রেশন**: `supabase/migrations/` ফোল্ডারে থাকা SQL ফাইলসমূহ idempotent (`IF NOT EXISTS`, `ON CONFLICT DO NOTHING`)।

---

## ২. Supabase প্রজেক্ট সেটআপ ও ডাটাবেজ কনফিগারেশন

১. [Supabase](https://supabase.com) এ নতুন প্রজেক্ট তৈরি করুন।
২. **SQL Editor** খুলে ক্রমানুসারে নিচের ৫টি মাইগ্রেশন ফাইল রান করুন:
   - `supabase/migrations/001_initial_schema.sql` (মূল টেবিল ও RLS)
   - `supabase/migrations/002_seed_defaults.sql` (ডিফল্ট ১৪টি ক্যাটাগরি ও সেটিংস)
   - `supabase/migrations/003_theme_presets.sql` (থিম প্রিসেট ও ডিজাইন টোকেন)
   - `supabase/migrations/004_auth_storage_hardening.sql` (অথেনটিকেশন ও স্টোরেজ বাকেট সুরক্ষা)
   - `supabase/migrations/005_users_roles_permissions.sql` (RBAC রোল ও পারমিশন সিস্টেম)
৩. **Authentication -> Providers -> Email** এ গিয়ে **Confirm Email** আপনার প্রয়োজন অনুযায়ী সেট করুন এবং **Allow new users to sign up** বন্ধ (Disable) রাখুন যাতে কেউ পাবলিক রেজিস্ট্রেশন করতে না পারে।

### সুপার অ্যাডমিন অ্যাকাউন্ট তৈরি

১. Supabase Dashboard -> **Authentication -> Users -> Add User** এ গিয়ে আপনার নির্ধারিত সুপার অ্যাডমিন ইমেইল ও শক্তিশালী পাসওয়ার্ড দিয়ে ইউজার তৈরি করুন।
২. তৈরি হওয়া ইউজারের **User UID** কপি করুন।
৩. SQL Editor-এ নিচের কোয়েরিটি রান করুন:

```sql
INSERT INTO public.admin_profiles (user_id, full_name, email, role)
VALUES (
  'YOUR_AUTH_USER_UUID',
  'প্রধান সম্পাদক',
  'admin@kushiaraexpress.com',
  'super_admin'
);
```

---

## ৩. Row Level Security (RLS) ও Storage যাচাই

- `001_initial_schema.sql` ও `005_users_roles_permissions.sql` স্বয়ংক্রিয়ভাবে সব টেবিলে RLS সক্রিয় করে এবং `public.is_super_admin()` ও `public.has_permission(TEXT)` ফাংশনের মাধ্যমে কেবল অনুমোদিত রোলকে সম্পাদনার অনুমতি দেয়।
- `news-media` নামের পাবলিক রিড Storage বাকেট তৈরি হয় যেখানে সর্বোচ্চ ৫ মেগাবাইট (`jpeg`, `png`, `webp`, `gif`) ছবি কেবল অনুমোদিত অ্যাডমিন/এডিটর আপলোড করতে পারবেন।

---

## ৪. এনভায়রনমেন্ট ভ্যারিয়েবল (Environment Variables)

> **গুরুত্বপূর্ণ নিরাপত্তা সতর্কতা**: কখনোই `SUPABASE_SERVICE_ROLE_KEY`, `ADMIN_SESSION_SECRET` বা `SUPER_ADMIN_PASSWORD` ব্রাউজার কোডে বা `VITE_` প্রিফিক্স দিয়ে ব্যবহার করবেন না। প্রোডাকশনে কোনো ডিফল্ট বা দুর্বল পাসওয়ার্ড (`Kushiara@2026!` ইত্যাদি) রাখবেন না।

Netlify বা Cloud Run Environment Variables এ নিচের ভ্যারিয়েবলগুলো যোগ করুন:

| ভ্যারিয়েবল | কোথায় ব্যবহৃত হয় | মান |
|---|---|---|
| `VITE_SUPABASE_URL` | ব্রাউজার ক্লায়েন্ট (বিল্ড ও সার্ভার রানটাইম ইনজেকশন) | `https://xxxx.supabase.co` |
| `VITE_SUPABASE_ANON_KEY` | ব্রাউজার ক্লায়েন্ট (RLS সুরক্ষিত) | আপনার Supabase Anon/Publishable Key |
| `VITE_SITE_URL` | ক্যানোনিকাল ও শেয়ার URL | `https://your-domain.com` |
| `SUPABASE_URL` | Server-side (`server.ts` / Netlify Functions) | `https://xxxx.supabase.co` |
| `SUPABASE_ANON_KEY` | Server-side OG মেটা ও পাবলিক রিড | আপনার Supabase Anon Key |
| `SUPABASE_SERVICE_ROLE_KEY` | শুধুমাত্র `admin-verify` ফাংশন (ঐচ্ছিক) | আপনার Supabase Service Role Key |
| `SUPER_ADMIN_EMAIL` | সার্ভার-সাইড সুপার অ্যাডমিন বুটস্ট্র্যাপ | `admin@kushiaraexpress.com` |
| `SUPER_ADMIN_PASSWORD` | প্রোডাকশন সুপার অ্যাডমিন শক্তিশালী পাসওয়ার্ড | কমপক্ষে ১২+ অক্ষরের শক্তিশালী পাসওয়ার্ড |
| `ADMIN_SESSION_SECRET` | প্রোডাকশন HMAC সেশন টোকেন সাইনিং | দীর্ঘ র‍্যান্ডম স্ট্রিং (৬৪ অক্ষর) |

---

## ৫. Cloud Run ও Netlify প্রোডাকশন ডিপ্লয়মেন্ট

### Cloud Run / Node.js সার্ভার (`server.ts`)
১. প্রোডাকশন বান্ডেল তৈরি করুন:
   ```bash
   npm run build
   ```
২. `NODE_ENV=production` এবং `PORT=3000` (অথবা Cloud Run `PORT`) সহ সার্ভার চালু করুন:
   ```bash
   NODE_ENV=production npm start
   ```
   (`npm start` স্বয়ংক্রিয়ভাবে `node server.ts` চালায়। `server.ts` প্রতিটি পাবলিক রুটে `VITE_SUPABASE_URL` ও `VITE_SUPABASE_ANON_KEY` নিরাপদভাবে রানটাইম কনফিগ হিসেবে ইনজেক্ট করে এবং `/`, `/category/:slug`, `/news/:slug`-এর জন্য সার্ভার-সাইড Open Graph ও Twitter Card মেটাডাটা রেন্ডার করে।)
৩. **Cloud Run Public Access**: Cloud Run সার্ভিসে `--allow-unauthenticated` (allUsers -> Cloud Run Invoker) চালু রাখুন এবং শেয়ার করার সময় সর্বদা পাবলিক/শেয়ার্ড URL (`https://ais-pre-...` বা কাস্টম ডোমেইন) ব্যবহার করুন—ডেভেলপার ওয়ার্কবেঞ্চ URL (`ais-dev-...`) নয়।

### GitHub ও Netlify ডিপ্লয়মেন্ট
১. আপনার GitHub অ্যাকাউন্টে একটি নতুন প্রাইভেট রিপোজিটরি তৈরি করুন।
২. প্রজেক্ট কোড পুশ করুন:
   ```bash
   git init
   git add .
   git commit -m "Initial production release: Kushiara Express"
   git branch -M main
   git remote add origin https://github.com/YOUR_USERNAME/kushiara-express.git
   git push -u origin main
   ```
৩. Netlify Dashboard -> **Add new site -> Import an existing project -> GitHub** নির্বাচন করুন।
৪. Build Command: `npm run build` এবং Publish Directory: `dist` স্বয়ংক্রিয়ভাবে `netlify.toml` থেকে লোড হবে।
৫. এনভায়রনমেন্ট ভ্যারিয়েবল সেট করে **Deploy site** ক্লিক করুন।

---

## ৬. সমস্যা সমাধান ও WhatsApp/Facebook Preview যাচাই

- **WhatsApp/Messenger/Facebook শেয়ারে "Cookie check" বা ছবি না দেখালে**:
  - নিশ্চিত করুন আপনি **পাবলিক/শেয়ার্ড URL** শেয়ার করছেন (AI Studio-র `ais-dev-...` প্রাইভেট ওয়ার্কবেঞ্চ লিংক নয়)।
  - সার্ভার `X-Forwarded-Host` ও `X-Forwarded-Proto` থেকে স্বয়ংক্রিয়ভাবে সঠিক `https://` URL তৈরি করে এবং `/og-cover.jpg` ও `/brand-logo.jpg` কোনোরকম কুকি বা লগইন ছাড়াই (`200 OK`) পরিবেশন করে।
  - [Meta Sharing Debugger](https://developers.facebook.com/tools/debug/)-এ পাবলিক URL দিয়ে **Scrape Again** ক্লিক করুন।
- **অ্যাডমিন লগইনে "Unauthorized" দেখালে**:
  - `public.admin_profiles` টেবিলে ওই ইউজারের `user_id`, `is_active = true` এবং `role = 'super_admin'` (অথবা অনুমোদিত রোল) যুক্ত আছে কি না নিশ্চিত করুন।
- **ছবি আপলোড না হলে**:
  - ফাইলটি অবশ্যই JPG, PNG, WebP বা GIF এবং ৫ মেগাবাইটের কম হতে হবে এবং Storage bucket `news-media` এর RLS পলিসি যাচাই করুন।

