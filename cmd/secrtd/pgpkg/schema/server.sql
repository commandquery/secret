create table secrt.server (
    server uuid not null primary key default gen_random_uuid(),

    -- The signing and encryption keys for talking to server itself.
    private_box_key bytea not null,
    public_box_key bytea not null,
    private_sign_key bytea not null,
    public_sign_key bytea not null
)