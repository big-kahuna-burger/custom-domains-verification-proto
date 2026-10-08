-- The identity provider's custom domains (F0-112). Additive while the pre-0.0.1 baseline
-- remains squashed.
DO $$ BEGIN
    CREATE TYPE "CUSTOM_DOMAIN_STATE" AS ENUM (
        'pending',
        'verified',
        'active',
        'verification_lost',
        'failed',
        'removed'
    );
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

CREATE TABLE IF NOT EXISTS "CustomDomain" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "host" TEXT NOT NULL,
    "state" "CUSTOM_DOMAIN_STATE" NOT NULL DEFAULT 'pending',
    "challengeHash" CHAR(64) NOT NULL,
    "challengeExpiresAt" TIMESTAMP(3) WITH TIME ZONE NOT NULL,
    "lastCheckedAt" TIMESTAMP(3) WITH TIME ZONE,
    "verifiedAt" TIMESTAMP(3) WITH TIME ZONE,
    "lastFailureReason" TEXT,
    "createdAt" TIMESTAMP(3) WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "CustomDomain_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX IF NOT EXISTS "CustomDomain_active_host_key"
    ON "CustomDomain"("host") WHERE "state" <> 'removed';
CREATE INDEX IF NOT EXISTS "CustomDomain_created_idx"
    ON "CustomDomain"("createdAt");

-- One advisory transaction lock serializes the count for the whole table. Because it is acquired
-- by a database trigger, every writer shares the same limit even when application workers race.
CREATE OR REPLACE FUNCTION "CustomDomain_enforce_limit"() RETURNS trigger AS $$
DECLARE
    active_count INTEGER;
BEGIN
    IF NEW."state" = 'removed' THEN
        RETURN NEW;
    END IF;

    PERFORM pg_advisory_xact_lock(112);
    SELECT count(*) INTO active_count
      FROM "CustomDomain"
     WHERE "state" <> 'removed'
       AND "id" <> NEW."id";

    IF active_count >= 10 THEN
        RAISE EXCEPTION 'this identity provider cannot hold more than 10 custom domains'
            USING ERRCODE = '23514', CONSTRAINT = 'CustomDomain_limit_check';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DO $$ BEGIN
    CREATE TRIGGER "CustomDomain_limit"
        BEFORE INSERT OR UPDATE OF "state" ON "CustomDomain"
        FOR EACH ROW EXECUTE FUNCTION "CustomDomain_enforce_limit"();
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;
