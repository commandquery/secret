create table secrt.message (
    primary key (server, peer, message),

    foreign key (server) references secrt.server,

    server uuid not null,
    peer uuid not null,
    message uuid not null,
	received timestamptz not null,
	claims bytea not null,     -- contains the sending peer alias, server-sealed
    metadata bytea,
	payload bytea not null
)