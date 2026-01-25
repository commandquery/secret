create table secrt.peer (
    primary key (server, peer),

    server uuid not null references secrt.server (server),
    peer uuid not null default gen_random_uuid(),
    alias text not null,
    public_box_key bytea not null
);

create index peer_alias_idx on secrt.peer (server, alias);