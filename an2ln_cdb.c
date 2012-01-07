#include <fcntl.h>
#include <string.h>
#include <stdlib.h>

#include <krb5.h>
#include <krb5/an2ln_plugin.h>

#include <cdb.h>

#define RULE_CDB	"CDB:"

static krb5_error_code
an2ln_cdb_plug_init(krb5_context context, void **ctx)
{
    *ctx = NULL;
    return 0;
}

static void
an2ln_cdb_plug_fini(void *ctx)
{
}

static krb5_error_code
an2ln_cdb_plug_an2ln(void *plug_ctx, krb5_context context,
		     const char *rule,
		     krb5_const_principal aname,
		     set_result_f set_res_f, void *set_res_ctx)
{
    krb5_error_code ret;
    const char *cdb_fname;
    struct cdb the_cdb, *cdb = NULL;
    unsigned vlen, vpos;
    int fd;
    char *astring = NULL;
    char lname[1024];

    if (strncmp(rule, RULE_CDB, strlen(RULE_CDB) != 0))
	return KRB5_PLUGIN_NO_HANDLE;

    cdb_fname = &rule[strlen(RULE_CDB)];
    if (!*cdb_fname)
	return KRB5_PLUGIN_NO_HANDLE;

    ret = krb5_unparse_name(context, aname, &astring);
    if (ret)
	return ret;

    ret = KRB5_PLUGIN_NO_HANDLE;
    fd = open(cdb_fname, O_RDONLY);
    if (fd == -1)
	goto done;

    if (cdb_init(&the_cdb, fd))
	goto done;

    cdb = &the_cdb;

    if (cdb_find(cdb, astring, strlen(astring)) > 0) {
	vpos = cdb_datapos(cdb);
	vlen = cdb_datalen(cdb);

	if (vlen < sizeof(lname)) {
	    cdb_read(cdb, lname, vlen, vpos);
	    lname[vlen] = '\0';
	    ret = 0;
	}
    }

    if (ret == 0) {
	if (!lname[0]) {
	    ret = KRB5_NO_LOCALNAME;
	    goto done;
	}

	ret = set_res_f(set_res_ctx, lname);
    }

done:
    free(astring);
    close(fd);
    if (cdb)
	cdb_free(cdb);
    return ret;
}

krb5plugin_an2ln_ftable an2ln = {
    0,
    an2ln_cdb_plug_init,
    an2ln_cdb_plug_fini,
    an2ln_cdb_plug_an2ln,
};
