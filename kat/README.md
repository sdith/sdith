# NIST KAT's generator template

The folder `sdith_cat1_short` is used as a template 
for all the KAT's *.rsp files generation.

The files PQCgenKAT_sign.c, rng.c, rng.h and 
the functions declared  in api.h are 
the official API and shall not be modified 
(except for the constants defined in api.h).
sign.c implement the KAT's api.h using sdith.

`kat_api_gen.c` is a small utility used to generate 
the `api.h` for all the sdith parameters. 