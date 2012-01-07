
libdir = $(prefix)/lib/plugin/krb5/

lib_LTLIBRARIES = an2ln_cdb.la

an2ln_cdb_la_SOURCES = an2ln_cdb.c

#
# Let's be a tad more aggressive about warnings:

an2ln_cdb_la_CPPFLAGS  = -Werror
an2ln_cdb_la_CPPFLAGS += -Wall -Wstrict-prototypes -Wmissing-prototypes
an2ln_cdb_la_CPPFLAGS += -Wpointer-arith -Wno-sign-compare
an2ln_cdb_la_CPPFLAGS += -Wno-traditional -Wreturn-type -Wswitch
an2ln_cdb_la_CPPFLAGS += -Wno-shadow -Wcast-qual -Wwrite-strings
an2ln_cdb_la_CPPFLAGS += -Wextra -Wno-unused-parameter -Wsign-compare

an2ln_cdb_la_LDFLAGS  = -module -avoid-version
