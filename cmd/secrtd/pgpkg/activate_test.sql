--
-- Test the activation function. This is obviously a critical function in the server.
--
create or replace
    function secrt.activate_test()
      returns void language 'plpgsql' as $$
    declare
        _token bytea;
        _code integer;
        _alias text = 'test@example.com';
        _public_key bytea = gen_random_bytes(32);
        _activation secrt.activation;
        _server uuid = gen_random_uuid();

    begin
        insert into secrt.server (server, secret_box_key, private_box_key, public_box_key, private_sign_key, public_sign_key)
            values (_server, gen_random_bytes(16), gen_random_bytes(16), gen_random_bytes(16), gen_random_bytes(16), gen_random_bytes(16));

        select * into _token, _code from secrt.enrol(_server, _alias, _public_key);

        raise notice 'enrolled token: % code %', _token, _code;

        _activation = secrt.activate(_token, _code);

        perform ??(_activation.token = _token);
        perform ??(_activation.server = _server);
        perform ??(_activation.alias = _alias);
        perform ??(_activation.public_box_key = _public_key);

        perform 1 from secrt.peer where server=_server and alias=_alias;
        if not found then
            raise exception 'activated peer not found';
        end if;
    end;
$$;