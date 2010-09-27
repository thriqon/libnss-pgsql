CREATE TABLE "groups" (
	"gid" serial NOT NULL,
	"name" character varying(16) NOT NULL,
	"descr" character varying,
	"passwd" character varying(20),
	PRIMARY KEY ("gid")
);

CREATE TABLE "accounts" (
	"uid" serial NOT NULL,
	"login" character varying(8) NOT NULL,
	"passwd" character varying(30) NOT NULL,
	"shell" character varying DEFAULT '/bin/bash' NOT NULL,
	"homedir" character varying NOT NULL,
	"pwdexpire" timestamp,
	"enabled" bool DEFAULT 't' NOT NULL,
	"subnet" character varying(8),
	"modemserial" character varying(20),
	"deleted" bool DEFAULT 'f',
	PRIMARY KEY ("login")
);

CREATE TABLE "usergroups" (
	"gid" int4 NOT NULL,
	"uid" int4 NOT NULL,
	PRIMARY KEY ("gid", "uid"),
	CONSTRAINT "ug_gid_fkey" FOREIGN KEY ("gid") REFERENCES "groups"("gid"),
	CONSTRAINT "ug_uid_fkey" FOREIGN KEY ("uid") REFERENCES "accounts"("uid")
);
