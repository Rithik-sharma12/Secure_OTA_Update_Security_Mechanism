-- =============================================================================
-- SentinelOTA Supabase Database Schema
-- Run this script in the Supabase SQL Editor (https://supabase.com/dashboard)
-- =============================================================================

-- 1. Devices Table
CREATE TABLE IF NOT EXISTS public.devices (
    id TEXT PRIMARY KEY,
    device_type TEXT NOT NULL DEFAULT 'ESP32',
    current_version TEXT NOT NULL DEFAULT '1.0.0',
    ash_score INT NOT NULL DEFAULT 100,
    status TEXT NOT NULL DEFAULT 'Healthy',
    quarantined BOOLEAN NOT NULL DEFAULT FALSE,
    logs JSONB DEFAULT '[]'::jsonb,
    last_heartbeat TIMESTAMPTZ DEFAULT NOW(),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- 2. Firmware Releases Table
CREATE TABLE IF NOT EXISTS public.firmware_releases (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    version TEXT UNIQUE NOT NULL,
    version_n INT NOT NULL,
    device_family TEXT NOT NULL DEFAULT 'ESP32',
    manifest_signature TEXT,
    binary_url TEXT,
    sha256_hash TEXT,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- 3. Telemetry & Heartbeat History Table
CREATE TABLE IF NOT EXISTS public.telemetry_logs (
    id BIGSERIAL PRIMARY KEY,
    device_id TEXT REFERENCES public.devices(id) ON DELETE CASCADE,
    ash_score INT NOT NULL,
    status TEXT NOT NULL,
    event_type TEXT DEFAULT 'HEARTBEAT',
    message TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- 4. Audit Webhook Events Table
CREATE TABLE IF NOT EXISTS public.webhook_events (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    event_id TEXT UNIQUE NOT NULL,
    event_type TEXT NOT NULL,
    payload JSONB NOT NULL,
    status TEXT NOT NULL DEFAULT 'PENDING',
    attempts INT DEFAULT 0,
    next_retry_at TIMESTAMPTZ,
    error_log TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Enable Row Level Security (RLS)
ALTER TABLE public.devices ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.firmware_releases ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.telemetry_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.webhook_events ENABLE ROW LEVEL SECURITY;

-- Allow Public / Service Role access policy (Adjust for production RLS as needed)
CREATE POLICY "Allow service role full access" ON public.devices FOR ALL USING (true);
CREATE POLICY "Allow service role full access" ON public.firmware_releases FOR ALL USING (true);
CREATE POLICY "Allow service role full access" ON public.telemetry_logs FOR ALL USING (true);
CREATE POLICY "Allow service role full access" ON public.webhook_events FOR ALL USING (true);
