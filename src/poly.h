#ifndef _POLY_H_
#define _POLY_H_

#include <stdio.h>
#include <stdbool.h>
#include <stddef.h>
#include <setjmp.h>

enum polytoktype {
	POLY_TNONE,

	POLY_TEOF,
	POLY_TCOMMENT,

	POLY_TNUMBER,
	POLY_TSTRING,
	POLY_TIDENT,

	POLY_TBREAK,
	POLY_TCONTINUE,
	POLY_TDO,
	POLY_TELSE,
	POLY_TFOR,
	POLY_TIF,
	POLY_TWHILE,

	POLY_TADD,
	POLY_TSUB,
	POLY_TMUL,
	POLY_TDIV,
	POLY_TEXP,
	POLY_TLOR,
	POLY_TLAND,
	POLY_TEQL,
	POLY_TNEQ,
	POLY_TLT,
	POLY_TLEQ,
	POLY_TGT,
	POLY_TGEQ,
	POLY_TQUOTE,

	POLY_TPREINC,
	POLY_TPREDEC,
	POLY_TPOSTINC,
	POLY_TPOSTDEC,

	POLY_TINC,
	POLY_TDEC,
	POLY_TADDASSIGN,
	POLY_TSUBASSIGN,
	POLY_TMULASSIGN,
	POLY_TDIVASSIGN,
	POLY_TEXPASSIGN,
	POLY_TASSIGN,

	POLY_TCOMMA,
	POLY_TSEMI,

	POLY_TLPAREN,
	POLY_TRPAREN,
	POLY_TLBRACK,
	POLY_TRBRACK,
	POLY_TLBRACE,
	POLY_TRBRACE,
};

enum polyasttype {
	POLY_ANONE,
	POLY_ACOMMENT,
	POLY_AIF,
	POLY_AWHILE,
	POLY_ADOWHILE,
	POLY_AFOR,
	POLY_ABLOCK,
	POLY_ABREAK,
	POLY_ACONTINUE,
	POLY_AASSIGN,
	POLY_AINCDEC,
	POLY_ACALL,
	POLY_AUNOP,
	POLY_ABINOP,
	POLY_ASUB,
	POLY_APAREN,
	POLY_ANUMBER,
	POLY_ASTRING,
	POLY_AIDENT,
};

struct polyloc {
	char *name;
	size_t line;
	size_t col;
};

struct polytok {
	enum polytoktype type;
	struct polyloc loc;
	char *lit;
};

struct polystr {
	size_t len;
	size_t cap;
	char buf[];
};

struct polyscan;
struct polyparse;
struct polyfunc;
struct polystate;

typedef void (*polyscanerrcb)(struct polyscan *, struct polytok *, int, const char *, void *);
typedef void (*polyparseerrcb)(struct polyparse *, int, const char *, void *);

struct polynum {
	long n;
	long d;
};

struct polyscan {
	int ch;
	FILE *fp;
	struct polyloc loc;
	struct polystr *str;

	polyscanerrcb errcb;
	void *errud;
	size_t nerr;
};

struct polynode {
	struct polyloc loc;
	enum polyasttype type;

	struct polyloc nameloc;
	char *name;
	int arity;

	struct polyloc oploc;
	enum polytoktype op;
	struct polynum nval;
	char *sval;

	struct polyloc elseloc;
	struct polyloc whileloc;

	struct polyloc opening[1];
	struct polyloc closing[1];
	struct polyloc comma;
	struct polyloc csemi[2];
	struct polyloc semi;

	struct polynode *arg;
	struct polynode *node[4];
	struct polynode *next;
};

struct polyblock {
	union {
		struct polyblock *next;
		max_align_t align;
	};
	char data[];
};

typedef int (*polyvisitor_t)(struct polynode *, void *);

struct polyast {
	char *name;

	struct polyblock *arena;
	size_t arenasize;

	struct polynode *comhead, *comtail;
	struct polynode *stmts;
};

enum {
	POLY_PDECL = 1 << 0,
};

struct polyparse {
	int mode;

	struct polyast *ast;
	struct polyscan scan;
	struct polytok tok;
	jmp_buf top;

	struct polyfunc *func;
	size_t nfunc;

	bool inloop;
	polyparseerrcb errcb;
	void *errud;
	size_t nerr;
};

enum polyfmtstyle {
	POLY_SKR = 0,
	POLY_SALLMAN,
};

struct polyfmt {
	enum polyfmtstyle style;
	bool spaces;
	size_t tabstop;
};

struct polytabwriter {
	FILE *fp;
	bool spaces;
	size_t tabstop;
	size_t pos;
	int lastch;
};

struct polyprint {
	struct polyfmt fmt;
	FILE *fp;

	struct polynode *com;
	struct polyloc *loc;
	size_t ind;
	size_t col;

	struct polytabwriter tw;
	struct {
		struct polyloc *loc;
		int attr;
		const char *lit;
	} look[2];
	size_t looklen;
};

struct polyfunc {
	const char *name;
	void (*call)(struct polystate *, void *);
	int arity;
	bool ret;
};

struct polyvar {
	char **name;
	struct polynum **coef;
	size_t ncoef;
};

struct polystate {
	struct polyvar *var;
	size_t nvar;

	struct polyfunc *func;
	size_t nfunc;
};

int polyloccmp(struct polyloc *, struct polyloc *);

const char *polytoktypestr(enum polytoktype);

int polyscanfile(struct polyscan *, const char *, FILE *, polyscanerrcb, void *);
void polyscanclose(struct polyscan *);
void polyscan(struct polyscan *, struct polytok *);

void polyparseaddbuiltins(struct polyparse *, struct polyfunc *, size_t);
int polyparsefile(struct polyparse *, const char *, FILE *, polyparseerrcb, void *, int);
int polyparse(struct polyparse *, struct polyast *);
void polyparseclose(struct polyparse *);

void polyastprint(struct polyast *, FILE *);
void polyastvisitnode(struct polynode *, polyvisitor_t, void *);
void polyastfree(struct polyast *);

void polyprintinit(struct polyprint *, struct polyfmt *, FILE *);
void polyprintast(struct polyprint *, struct polyast *);

struct polyfunc *polydefbuiltins(size_t *);

int polyevaltree(struct polystate *, struct polyast *);
int polyevalnode(struct polystate *, struct polynode *n);

int polynuminitstr(struct polynum *, const char *);
char *polynumstr(struct polynum *, char *, size_t);
void polynumcanon(struct polynum *);
void polynumadd(struct polynum *, struct polynum *, struct polynum *);
void polynumsub(struct polynum *, struct polynum *, struct polynum *);
void polynummul(struct polynum *, struct polynum *, struct polynum *);
void polynumdiv(struct polynum *, struct polynum *, struct polynum *);
void polynumexp(struct polynum *, struct polynum *, struct polynum *);

size_t polytwputs(struct polytabwriter *, const char *);
size_t polytwputsln(struct polytabwriter *, const char *);
size_t polytwputc(struct polytabwriter *, char);
void polytwflush(struct polytabwriter *);

#endif
