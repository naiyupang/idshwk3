global dict : table[addr] of set[string] = table();
event http_header (c: connection, is_orig: bool, name: string, value: string)
{
    if(name=="USER-AGENT")
    {
            if(c$id$orig_h in dict)
            {
                    if(!(to_lower(value) in dict[c$id$orig_h]))
                    {
                            add dict[c$id$orig_h][to_lower(value)];
                    }
            }
            else
            {
                    dict[c$id$orig_h]=set(to_lower(value));
            }
    }
}
event zeek_done()
{
	for (Addr, Set in dict)
	{
		if(|Set|>=3)
		{
			print fmt("%s is a proxy",Addr);
		}
	}
}
