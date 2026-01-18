create table secrt.message (
    primary key (server, peer, message),

    foreign key (server) references secrt.server,
    foreign key (server, sender) references secrt.peer (server, peer),

    server uuid not null,
    peer uuid not null,
    message uuid not null,
    sender uuid not null,
	received timestamptz not null,
	metadata bytea,
	payload bytea not null
)