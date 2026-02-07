--
-- the activate function finds the given activation key and deletes it.
-- it also deletes any expired keys. It then creates a new peer for the given
-- alias. Returns the peer ID and associated alias.
--
create or replace
    function secrt.activate(_token bytea, _code int, out _peer uuid, out _alias text)
       language 'plpgsql' as $$
    declare
        _activation secrt.activation;
    begin
        -- quick purge of old tokens
        delete from secrt.activation where expiry <= current_timestamp;
        delete from secrt.activation where token=_token and code=_code returning * into _activation;
        if not found then
            raise exception 'activation token not found';
        end if;

        perform 1 from secrt.peer where server=_activation.server and peer.alias=_activation.alias;
        if found then
            raise exception 'peer is already activated';
        end if;

        insert into secrt.peer (server, peer, alias, public_box_key)
            values (_activation.server, DEFAULT, _activation.alias, _activation.public_box_key)
            returning peer into _peer;

        _alias = _activation.alias;
        raise notice 'successfully activated alias %', _activation.alias;
    end;
$$;

