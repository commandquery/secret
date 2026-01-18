create table secrt.peer (
    primary key (server, peer),

    server uuid not null references secrt.server (server),
    peer uuid not null,
    alias text not null,
    public_box_key bytea not null,
    verified bool not null default false,    -- address has been verified
    marketing bool not null default false,   -- has allowed marketing comms
    operations bool not null default true    -- has disabled operational comms
);

create index peer_alias_idx on secrt.peer (server, alias);