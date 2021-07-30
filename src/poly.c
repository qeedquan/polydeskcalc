#define _GNU_SOURCE
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdint.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <math.h>
#include "poly.h"

#define nelem(x) (sizeof(x) / sizeof(x[0]))

struct oper {
	int prec;
	int rassoc;
};

static const struct oper binop[] = {
    [POLY_TLOR] = {1, 0},
    [POLY_TLAND] = {2, 0},
    [POLY_TLEQ] = {3, 0},
    [POLY_TLT] = {3, 0},
    [POLY_TGT] = {3, 0},
    [POLY_TGEQ] = {3, 0},
    [POLY_TNEQ] = {4, 0},
    [POLY_TEQL] = {4, 0},
    [POLY_TADD] = {5, 0},
    [POLY_TSUB] = {5, 0},
    [POLY_TMUL] = {6, 0},
    [POLY_TDIV] = {6, 0},
    [POLY_TEXP] = {7, 1},
};

enum {
	BINOP = 1 << 0,
	UNOP = 1 << 1,
	EXPR = 1 << 2,
	STMT = 1 << 3,

	LEADSPACE = 1 << 4,
	TRAILSPACE = 1 << 5,
	INDENT = 1 << 6,
	NEWLINE = 1 << 7,
	SCOPE = 1 << 8,
	UNSCOPE = 1 << 9,
	NOINDENTCOL = 1 << 10,
	MERGELINE = 1 << 11,
	PADSPACES = 1 << 12,
};

int
polyloccmp(struct polyloc *a, struct polyloc *b)
{
	if (a->line < b->line)
		return -1;
	if (a->line > b->line)
		return 1;
	if (a->col < b->col)
		return -1;
	if (a->col > b->col)
		return 1;
	return 0;
}

static unsigned
tokattr(enum polytoktype type)
{
	switch (type) {
	case POLY_TNUMBER:
	case POLY_TSTRING:
		return EXPR;
	case POLY_TADD:
	case POLY_TSUB:
		return EXPR | UNOP | BINOP;
	case POLY_TQUOTE:
		return EXPR | UNOP;
	case POLY_TMUL:
	case POLY_TDIV:
	case POLY_TEXP:
	case POLY_TLOR:
	case POLY_TLAND:
	case POLY_TEQL:
	case POLY_TNEQ:
	case POLY_TLT:
	case POLY_TLEQ:
	case POLY_TGT:
	case POLY_TGEQ:
		return EXPR | BINOP;
	case POLY_TCOMMA:
	case POLY_TLPAREN:
	case POLY_TLBRACK:
	case POLY_TRBRACK:
		return EXPR;
	case POLY_TIDENT:
		return EXPR | STMT;
	case POLY_TLBRACE:
	case POLY_TINC:
	case POLY_TDEC:
	case POLY_TPREINC:
	case POLY_TPREDEC:
	case POLY_TPOSTINC:
	case POLY_TPOSTDEC:
	case POLY_TADDASSIGN:
	case POLY_TSUBASSIGN:
	case POLY_TMULASSIGN:
	case POLY_TDIVASSIGN:
	case POLY_TEXPASSIGN:
	case POLY_TASSIGN:
	case POLY_TCONTINUE:
	case POLY_TBREAK:
	case POLY_TDO:
	case POLY_TIF:
	case POLY_TELSE:
	case POLY_TFOR:
	case POLY_TWHILE:
		return STMT;
	case POLY_TSEMI:
	case POLY_TRBRACE:
	case POLY_TRPAREN:
		return 0;
	default:
		break;
	}
	return 0;
}

const char *
polytoktypestr(enum polytoktype type)
{
	switch (type) {
	case POLY_TNONE:
		return "<none>";
	case POLY_TEOF:
		return "<eof>";
	case POLY_TCOMMENT:
		return "<comment>";
	case POLY_TNUMBER:
		return "<number>";
	case POLY_TSTRING:
		return "<string>";
	case POLY_TIDENT:
		return "<ident>";
	case POLY_TBREAK:
		return "break";
	case POLY_TCONTINUE:
		return "continue";
	case POLY_TDO:
		return "do";
	case POLY_TELSE:
		return "else";
	case POLY_TFOR:
		return "for";
	case POLY_TIF:
		return "if";
	case POLY_TWHILE:
		return "while";
	case POLY_TADD:
		return "+";
	case POLY_TSUB:
		return "-";
	case POLY_TMUL:
		return "*";
	case POLY_TDIV:
		return "/";
	case POLY_TEXP:
		return "^";
	case POLY_TQUOTE:
		return "'";
	case POLY_TINC:
	case POLY_TPREINC:
	case POLY_TPOSTINC:
		return "++";
	case POLY_TDEC:
	case POLY_TPREDEC:
	case POLY_TPOSTDEC:
		return "--";
	case POLY_TLOR:
		return "||";
	case POLY_TLAND:
		return "&&";
	case POLY_TADDASSIGN:
		return "+=";
	case POLY_TSUBASSIGN:
		return "-=";
	case POLY_TMULASSIGN:
		return "*=";
	case POLY_TDIVASSIGN:
		return "/=";
	case POLY_TEXPASSIGN:
		return "^=";
	case POLY_TASSIGN:
		return "=";
	case POLY_TEQL:
		return "==";
	case POLY_TNEQ:
		return "!=";
	case POLY_TLT:
		return "<";
	case POLY_TGT:
		return ">";
	case POLY_TLEQ:
		return "<=";
	case POLY_TGEQ:
		return ">=";
	case POLY_TCOMMA:
		return ",";
	case POLY_TSEMI:
		return ";";
	case POLY_TLPAREN:
		return "(";
	case POLY_TRPAREN:
		return ")";
	case POLY_TLBRACK:
		return "[";
	case POLY_TRBRACK:
		return "]";
	case POLY_TLBRACE:
		return "{";
	case POLY_TRBRACE:
		return "}";
	}
	return "<unknown>";
}

int
polyscanfile(struct polyscan *s, const char *name, FILE *fp, polyscanerrcb errcb, void *errud)
{
	memset(s, 0, sizeof(*s));

	s->fp = fp;
	s->str = calloc(1, sizeof(*s->str) + BUFSIZ);
	s->loc = (struct polyloc){
	    .name = strdup(name),
	    .line = 1,
	    .col = 1,
	};
	if (!s->str || !s->loc.name)
		goto err;
	s->str->cap = BUFSIZ;

	s->errcb = errcb;
	s->errud = errud;
	s->ch = INT_MIN;
	return 0;

err:
	polyscanclose(s);
	return -errno;
}

void
polyscanclose(struct polyscan *s)
{
	free(s->str);
	free(s->loc.name);
}

static void
scanerr(struct polyscan *s, struct polytok *t, int err, const char *fmt, ...)
{
	char msg[80];
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(msg, sizeof(msg), fmt, ap);
	va_end(ap);

	s->nerr++;
	if (s->errcb)
		s->errcb(s, t, err, msg, s->errud);
}

static void
addlitch(struct polyscan *s, struct polytok *t, int ch, bool *oom)
{
	struct polystr *p;

	if (*oom)
		return;

	p = s->str;
	if (p->len >= p->cap) {
		if (p->len >= SSIZE_MAX)
			goto oom;

		p = realloc(p, sizeof(*p) + p->cap + BUFSIZ);
		if (!p)
			goto oom;
		p->cap += BUFSIZ;

		s->str = p;
	}

	p->buf[p->len++] = ch;
	return;

oom:
	*oom = true;
	scanerr(s, t, ENOMEM, "%s", strerror(ENOMEM));
}

static void
nextch(struct polyscan *s)
{
	struct polyloc *l;

	if (s->ch == EOF)
		return;

	l = &s->loc;
	if (s->ch == '\n') {
		l->line++;
		l->col = 1;
	} else
		l->col++;
	s->ch = fgetc(s->fp);
}

static void
scanlitch(struct polyscan *s, struct polytok *t, int ch, bool *oom)
{
	addlitch(s, t, ch, oom);
	nextch(s);
}

static void
scanws(struct polyscan *s)
{
	while (isspace(s->ch))
		nextch(s);
}

static bool
incom(int ch)
{
	return ch != '\n' && ch != EOF;
}

static bool
inident(int ch)
{
	return ch == '_' || isalnum(ch);
}

static void
unescape(char *s)
{
	size_t i, j;

	for (i = j = 0; s[i]; i++) {
		if (s[i] != '\\') {
			s[j++] = s[i];
		} else {
			switch (s[++i]) {
			case 'a':
				s[j++] = '\a';
				break;
			case 'b':
				s[j++] = '\b';
				break;
			case 'f':
				s[j++] = '\f';
				break;
			case 'n':
				s[j++] = '\n';
				break;
			case 'r':
				s[j++] = '\r';
				break;
			case 't':
				s[j++] = '\t';
				break;
			case 'v':
				s[j++] = '\v';
				break;
			case '\'':
				s[j++] = '\'';
				break;
			case '"':
				s[j++] = '"';
				break;
			case '?':
				s[j++] = '\?';
				break;
			default:
				s[j++] = '\\';
				s[j++] = s[i];
				break;
			}
		}
	}
	s[j] = '\0';
}

static void
scanrun(struct polyscan *s, struct polytok *t, int type, int ch, bool (*in)(int))
{
	bool oom;

	t->type = type;
	s->str->len = 0;

	oom = false;
	do {
		scanlitch(s, t, ch, &oom);
		ch = s->ch;
	} while (in(ch));
	addlitch(s, t, '\0', &oom);

	if (!oom)
		t->lit = s->str->buf;
}

static void
scansym2(struct polyscan *s, struct polytok *t, int type1, int ch2, int type2)
{
	t->type = type1;
	if (s->ch == ch2) {
		t->type = type2;
		nextch(s);
	}
}

static void
scansym3(struct polyscan *s, struct polytok *t, int type1, int ch2, int type2, int ch3, int type3)
{
	t->type = type1;
	if (s->ch == ch2) {
		t->type = type2;
		nextch(s);
	} else if (s->ch == ch3) {
		t->type = type3;
		nextch(s);
	}
}

static int
scannum(struct polyscan *s, struct polytok *t)
{
	bool oom;

	t->type = POLY_TNUMBER;
	s->str->len = 0;

	oom = false;
	if (s->ch == '.')
		scanlitch(s, t, s->ch, &oom);

	while (isdigit(s->ch))
		scanlitch(s, t, s->ch, &oom);

	if (s->ch == '.')
		scanlitch(s, t, s->ch, &oom);

	while (isdigit(s->ch))
		scanlitch(s, t, s->ch, &oom);

	if (s->ch == 'e' || s->ch == 'E') {
		scanlitch(s, t, s->ch, &oom);
		if (s->ch == '+' || s->ch == '-')
			scanlitch(s, t, s->ch, &oom);
		if (!isdigit(s->ch)) {
			scanerr(s, t, EINVAL, "missing numbers after exponent");
			return -1;
		}
	}

	while (isdigit(s->ch))
		scanlitch(s, t, s->ch, &oom);

	addlitch(s, t, '\0', &oom);

	if (!oom)
		t->lit = s->str->buf;

	return 0;
}

static int
scanstr(struct polyscan *s, struct polytok *t)
{
	bool oom;

	t->type = POLY_TSTRING;
	s->str->len = 0;

	oom = false;
	scanlitch(s, t, s->ch, &oom);
	while (s->ch != '"' && s->ch != EOF) {
		if (s->ch == '\\') {
			scanlitch(s, t, s->ch, &oom);
			if (s->ch == EOF)
				break;
			scanlitch(s, t, s->ch, &oom);
		} else
			scanlitch(s, t, s->ch, &oom);
	}
	if (s->ch == '"')
		scanlitch(s, t, s->ch, &oom);
	else if (s->ch == EOF) {
		scanerr(s, t, EINVAL, "unterminated string");
		return -1;
	}

	addlitch(s, t, '\0', &oom);

	if (!oom) {
		t->lit = s->str->buf;
		unescape(t->lit);
	}

	return 0;
}

static void
lookupkw(struct polytok *t)
{
	static const struct {
		enum polytoktype type;
		const char *str;
	} kw[] = {
	    {POLY_TBREAK, "break"},
	    {POLY_TCONTINUE, "continue"},
	    {POLY_TDO, "do"},
	    {POLY_TELSE, "else"},
	    {POLY_TFOR, "for"},
	    {POLY_TIF, "if"},
	    {POLY_TWHILE, "while"},
	};

	if (!t->lit)
		return;

	size_t min, max, mid;
	int cmp;

	min = 0;
	max = sizeof(kw) / sizeof(kw[0]);
	while (max > min) {
		mid = (max + min) / 2;
		cmp = strcmp(t->lit, kw[mid].str);
		if (cmp == 0) {
			t->type = kw[mid].type;
			t->lit = NULL;
			break;
		} else if (cmp > 0)
			min = mid + 1;
		else if (cmp < 0)
			max = mid;
	}
}

void
polyscan(struct polyscan *s, struct polytok *t)
{
	int ch;

	if (s->ch == INT_MIN)
		s->ch = fgetc(s->fp);

loop:
	scanws(s);

	t->loc = s->loc;
	t->lit = NULL;

	if (s->ch == '#') {
		scanrun(s, t, POLY_TCOMMENT, s->ch, incom);
		return;
	}
	if (isdigit(s->ch) || s->ch == '.') {
		if (scannum(s, t) < 0)
			goto loop;
		return;
	}
	if (s->ch == '_' || isalpha(s->ch)) {
		scanrun(s, t, POLY_TIDENT, s->ch, inident);
		lookupkw(t);
		return;
	}
	if (s->ch == '"') {
		if (scanstr(s, t) < 0)
			goto loop;
		return;
	}

	ch = s->ch;
	nextch(s);
	switch (ch) {
	case EOF:
		t->type = POLY_TEOF;
		break;
	case '+':
		scansym3(s, t, POLY_TADD, '+', POLY_TINC, '=', POLY_TADDASSIGN);
		break;
	case '-':
		scansym3(s, t, POLY_TSUB, '-', POLY_TDEC, '=', POLY_TSUBASSIGN);
		break;
	case '*':
		scansym2(s, t, POLY_TMUL, '=', POLY_TMULASSIGN);
		break;
	case '/':
		scansym2(s, t, POLY_TDIV, '=', POLY_TDIVASSIGN);
		break;
	case '^':
		scansym2(s, t, POLY_TEXP, '=', POLY_TEXPASSIGN);
		break;
	case '\'':
		t->type = POLY_TQUOTE;
		break;
	case '<':
		scansym2(s, t, POLY_TLT, '=', POLY_TLEQ);
		break;
	case '>':
		scansym2(s, t, POLY_TGT, '=', POLY_TGEQ);
		break;
	case '=':
		scansym2(s, t, POLY_TASSIGN, '=', POLY_TEQL);
		break;
	case '!':
		if (s->ch != '=')
			goto invalid;
		t->type = POLY_TNEQ;
		nextch(s);
		break;
	case '|':
		if (s->ch != '|')
			goto invalid;
		t->type = POLY_TLOR;
		nextch(s);
		break;
	case '&':
		if (s->ch != '&')
			goto invalid;
		t->type = POLY_TLAND;
		nextch(s);
		break;
	case '(':
		t->type = POLY_TLPAREN;
		break;
	case ')':
		t->type = POLY_TRPAREN;
		break;
	case '[':
		t->type = POLY_TLBRACK;
		break;
	case ']':
		t->type = POLY_TRBRACK;
		break;
	case '{':
		t->type = POLY_TLBRACE;
		break;
	case '}':
		t->type = POLY_TRBRACE;
		break;
	case ',':
		t->type = POLY_TCOMMA;
		break;
	case ';':
		t->type = POLY_TSEMI;
		break;
	default:
	invalid:
		if (isprint(ch) && ch != '\n')
			scanerr(s, t, EINVAL, "invalid character '%c' encountered", ch);
		else
			scanerr(s, t, EINVAL, "invalid character %d encountered", ch);
		goto loop;
	}
}

static struct polynode *nod(struct polyparse *, int, ...);
static struct polynode *parseexpr(struct polyparse *);
static struct polynode *parsestmt(struct polyparse *);
static struct polynode *parsestmts(struct polyparse *);
static void parsecall(struct polyparse *, struct polynode *, bool);
static void prstmt(struct polyprint *, struct polynode *, bool, bool, bool);
static void prctrlblock(struct polyprint *, struct polynode *, bool);

static void
parseerr(struct polyparse *p, int err, const char *fmt, ...)
{
	char msg[128];
	va_list ap;

	p->nerr++;
	if (p->errcb) {
		va_start(ap, fmt);
		vsnprintf(msg, sizeof(msg), fmt, ap);
		va_end(ap);
		p->errcb(p, err, msg, p->errud);
	}
}

static void
parsescanerr(struct polyscan *s, struct polytok *t, int err, const char *msg, void *p)
{
	parseerr(p, err, "%s", msg);
	(void)s;
	(void)t;
}

static void *
pmalloc(struct polyparse *p, size_t size)
{
	struct polyblock *b;

	b = calloc(1, sizeof(*b) + size);
	if (!b) {
		parseerr(p, ENOMEM, "%s", strerror(ENOMEM));
		siglongjmp(p->top, 1);
	}

	b->next = p->ast->arena;
	p->ast->arena = b;
	p->ast->arenasize += sizeof(*b) + size;
	return b->data;
}

static char *
pstrdup(struct polyparse *p, char *s)
{
	char *t;

	if (s == NULL)
		return NULL;
	t = pmalloc(p, strlen(s) + 1);
	return strcpy(t, s);
}

static void
nexttok(struct polyparse *p)
{
	struct polyast *a;
	struct polynode *n;

loop:
	a = p->ast;
	polyscan(&p->scan, &p->tok);
	p->tok.loc.name = a->name;
	if (p->tok.type == POLY_TCOMMENT) {
		n = nod(p, POLY_ACOMMENT, p->tok.lit);
		if (!a->comhead)
			a->comhead = a->comtail = n;
		else
			a->comtail = a->comtail->next = n;
		goto loop;
	}
}

static void
synctok(struct polyparse *p, int to)
{
	while (p->tok.type != POLY_TEOF) {
		switch (to) {
		case 's':
			switch (p->tok.type) {
			case POLY_TIDENT:
			case POLY_TIF:
			case POLY_TFOR:
			case POLY_TDO:
			case POLY_TWHILE:
			case POLY_TBREAK:
			case POLY_TCONTINUE:
				return;
			default:
				break;
			}
			break;

		case 'e':
			switch (p->tok.type) {
			case POLY_TSEMI:
			case POLY_TRPAREN:
			case POLY_TRBRACK:
			case POLY_TRBRACE:
				return;
			default:
				break;
			}
			break;
		}
		nexttok(p);
	}
}

static void
expect(struct polyparse *p, enum polytoktype type)
{
	if (p->tok.type != type)
		parseerr(p, EINVAL, "expected %s but got %s", polytoktypestr(type), polytoktypestr(p->tok.type));
	nexttok(p);
}

int
polyparsefile(struct polyparse *p, const char *name, FILE *fp, polyparseerrcb errcb, void *errud, int mode)
{
	struct polyfunc *func;
	size_t nfunc;
	int rv;

	memset(p, 0, sizeof(*p));
	p->mode = mode;
	p->errcb = errcb;
	p->errud = errud;

	func = polydefbuiltins(&nfunc);
	polyparseaddbuiltins(p, func, nfunc);

	if ((rv = polyscanfile(&p->scan, name, fp, parsescanerr, p)) < 0)
		return rv;

	return 0;
}

static struct polynode *
nod(struct polyparse *p, int t, ...)
{
	struct polynode *n;
	va_list ap;

	n = pmalloc(p, sizeof(*n));
	n->loc = p->tok.loc;
	n->type = t;

	va_start(ap, t);
	switch (t) {
	case POLY_ACOMMENT:
		n->sval = pstrdup(p, va_arg(ap, char *));
		break;

	case POLY_ANUMBER:
		n->sval = pstrdup(p, va_arg(ap, char *));
		polynuminitstr(&n->nval, n->sval);
		break;

	case POLY_AIDENT:
		n->nameloc = n->loc;
		n->name = pstrdup(p, va_arg(ap, char *));
		break;

	case POLY_ASTRING:
		n->sval = pstrdup(p, va_arg(ap, char *));
		break;

	case POLY_ABINOP:
		n->op = va_arg(ap, int);
		n->oploc = va_arg(ap, struct polyloc);
		break;

	case POLY_AUNOP:
		n->op = va_arg(ap, int);
		n->oploc = n->loc;
		break;
	}
	va_end(ap);

	return n;
}

static struct polynode *
parsesub(struct polyparse *p, struct polynode *n)
{
	struct polynode *m;

	n->opening[0] = p->tok.loc;
	nexttok(p);
	m = n;
	while (p->tok.type != POLY_TRBRACK) {
		m->name = pstrdup(p, p->tok.lit);
		m->nameloc = p->tok.loc;
		expect(p, POLY_TIDENT);

		m->oploc = p->tok.loc;
		m->op = POLY_TASSIGN;
		expect(p, POLY_TASSIGN);

		m->node[0] = parseexpr(p);
		if (p->tok.type != POLY_TCOMMA)
			break;
		m->comma = p->tok.loc;
		nexttok(p);

		m = m->node[1] = nod(p, POLY_ASUB);
	}
	if (!n->name)
		parseerr(p, EINVAL, "empty sub expression");
	n->closing[0] = p->tok.loc;
	expect(p, POLY_TRBRACK);

	return n;
}

static struct polynode *
parseprimary(struct polyparse *p)
{
	struct polynode *n, *m;
	bool once;

	n = NULL;
	switch (p->tok.type) {
	case POLY_TNUMBER:
		n = nod(p, POLY_ANUMBER, p->tok.lit);
		nexttok(p);
		break;

	case POLY_TSTRING:
		n = nod(p, POLY_ASTRING, p->tok.lit);
		nexttok(p);
		break;

	case POLY_TIDENT:
		n = nod(p, POLY_AIDENT, p->tok.lit);
		nexttok(p);
		break;

	case POLY_TADD:
	case POLY_TSUB:
	case POLY_TQUOTE:
		n = nod(p, POLY_AUNOP, p->tok.type);
		nexttok(p);
		n->node[0] = parseprimary(p);
		break;

	case POLY_TLPAREN:
		n = nod(p, POLY_APAREN);
		n->opening[0] = p->tok.loc;
		nexttok(p);
		n->node[0] = parseexpr(p);
		n->closing[0] = p->tok.loc;
		expect(p, POLY_TRPAREN);
		break;

	default:
		n = nod(p, POLY_ANONE);
		parseerr(p, EINVAL, "primary expression syntax error, got %s", polytoktypestr(p->tok.type));
		synctok(p, 'e');
		goto out;
	}

	once = false;
	for (;;) {
		switch (p->tok.type) {
		case POLY_TLPAREN:
			if (!once)
				parsecall(p, n, true);
			else
				goto out;
			break;
		case POLY_TLBRACK:
			m = nod(p, POLY_ASUB);
			m->node[2] = n;
			parsesub(p, m);
			n = m;
			break;
		default:
			goto out;
		}
		once = true;
	}
out:
	return n;
}

static struct polynode *
parseexpr(struct polyparse *p)
{
	struct polynode **stk, **nstk, *n;
	struct polyloc l;
	size_t len, cap;
	int t, nok;

	len = 0;
	cap = 8;
	stk = pmalloc(p, sizeof(*stk) * cap);
	stk[len++] = parseprimary(p);
	for (;;) {
		t = p->tok.type;
		l = p->tok.loc;
		nok = !(tokattr(t) & BINOP);
		while (len >= 3 && (nok || binop[stk[len - 2]->op].prec >= binop[t].prec + binop[t].rassoc)) {
			n = nod(p, POLY_ABINOP, stk[len - 2]->op, stk[len - 2]->loc);
			n->node[0] = stk[len - 3];
			n->node[1] = stk[len - 1];
			stk[len - 3] = n;
			len -= 2;
		}

		if (nok)
			break;

		if (len + 2 >= cap) {
			cap += 16;
			nstk = pmalloc(p, cap);
			memmove(nstk, stk, len * sizeof(*stk));
			stk = nstk;
		}
		stk[len++] = nod(p, POLY_ABINOP, t, l);
		nexttok(p);
		stk[len++] = parseprimary(p);
	}

	if (len != 1)
		parseerr(p, EINVAL, "expression syntax error");

	return stk[0];
}

static struct polynode *
parseblock(struct polyparse *p)
{
	struct polynode *n;

	n = nod(p, POLY_ABLOCK);
	n->opening[0] = p->tok.loc;
	nexttok(p);
	if (p->tok.type != POLY_TRBRACE)
		n->node[0] = parsestmts(p);
	n->closing[0] = p->tok.loc;
	expect(p, POLY_TRBRACE);
	return n;
}

static void
parsecall(struct polyparse *p, struct polynode *n, bool paren)
{
	struct polynode *m;
	size_t i;

	if (p->mode & POLY_PDECL) {
		for (i = 0; i < p->nfunc; i++) {
			if (!strcmp(p->func[i].name, n->name))
				break;
		}
		if (i == p->nfunc)
			parseerr(p, ENOENT, "undefined function %s", n->name);
	}

	n->type = POLY_ACALL;
	if (paren) {
		n->opening[0] = p->tok.loc;
		expect(p, POLY_TLPAREN);
	}
	n->arity = 0;

	m = n;
	for (;;) {
		if (!(tokattr(p->tok.type) & EXPR))
			break;

		m = m->arg = parseexpr(p);
		n->arity++;

		if (p->tok.type != POLY_TCOMMA)
			break;
		m->comma = p->tok.loc;
		expect(p, POLY_TCOMMA);
	}

	if (paren) {
		n->closing[0] = p->tok.loc;
		expect(p, POLY_TRPAREN);
	}
}

static struct polynode *
parseident(struct polyparse *p, enum polytoktype pre)
{
	struct polynode *n;

	n = nod(p, POLY_AASSIGN);
	if (pre) {
		n->type = POLY_AINCDEC;
		n->oploc = p->tok.loc;
		n->op = (pre == POLY_TINC) ? POLY_TPREINC : POLY_TPREDEC;
		nexttok(p);
	}
	n->name = pstrdup(p, p->tok.lit);
	n->nameloc = p->tok.loc;
	expect(p, POLY_TIDENT);

	if (n->op)
		return n;

	n->oploc = p->tok.loc;
	switch (p->tok.type) {
	case POLY_TLPAREN:
		if (!strcmp(n->name, "print"))
			parsecall(p, n, false);
		else
			parsecall(p, n, true);
		break;
	case POLY_TINC:
		n->type = POLY_AINCDEC;
		n->op = POLY_TPOSTINC;
		n->oploc = p->tok.loc;
		nexttok(p);
		break;
	case POLY_TDEC:
		n->type = POLY_AINCDEC;
		n->op = POLY_TPOSTDEC;
		n->oploc = p->tok.loc;
		nexttok(p);
		break;
	case POLY_TASSIGN:
	case POLY_TADDASSIGN:
	case POLY_TSUBASSIGN:
	case POLY_TMULASSIGN:
	case POLY_TDIVASSIGN:
	case POLY_TEXPASSIGN:
		n->op = p->tok.type;
		nexttok(p);
		n->node[0] = parseexpr(p);
		break;
	default:
		if (tokattr(p->tok.type) & EXPR)
			parsecall(p, n, false);
		else {
			parseerr(p, EINVAL, "invalid statement, got %s", polytoktypestr(p->tok.type));
			synctok(p, 's');
		}
		break;
	}

	return n;
}

static struct polynode *
parseif(struct polyparse *p)
{
	struct polynode *n;

	n = nod(p, POLY_AIF);
	nexttok(p);
	n->opening[0] = p->tok.loc;
	expect(p, POLY_TLPAREN);
	n->node[0] = parseexpr(p);
	n->closing[0] = p->tok.loc;
	expect(p, POLY_TRPAREN);
	n->node[1] = parsestmt(p);
	if (p->tok.type == POLY_TELSE) {
		n->elseloc = p->tok.loc;
		nexttok(p);
		n->node[2] = parsestmt(p);
	}
	return n;
}

static struct polynode *
parsewhile(struct polyparse *p)
{
	struct polynode *n;
	bool inloop;

	n = nod(p, POLY_AWHILE);
	nexttok(p);
	n->opening[0] = p->tok.loc;
	expect(p, POLY_TLPAREN);
	n->node[0] = parseexpr(p);
	n->closing[0] = p->tok.loc;
	expect(p, POLY_TRPAREN);
	inloop = p->inloop;
	p->inloop = true;
	n->node[1] = parsestmt(p);
	p->inloop = inloop;
	return n;
}

static struct polynode *
parsedowhile(struct polyparse *p)
{
	struct polynode *n;
	bool inloop;

	n = nod(p, POLY_ADOWHILE);
	nexttok(p);
	inloop = p->inloop;
	p->inloop = true;
	n->node[0] = parsestmt(p);
	p->inloop = inloop;
	n->whileloc = p->tok.loc;
	expect(p, POLY_TWHILE);
	n->opening[0] = p->tok.loc;
	expect(p, POLY_TLPAREN);
	n->node[1] = parseexpr(p);
	n->closing[0] = p->tok.loc;
	expect(p, POLY_TRPAREN);
	return n;
}

static struct polynode *
parsefor(struct polyparse *p)
{
	struct polynode *n;
	bool inloop;

	n = nod(p, POLY_AFOR);
	nexttok(p);
	n->opening[0] = p->tok.loc;
	expect(p, POLY_TLPAREN);
	if (p->tok.type != POLY_TSEMI)
		n->node[0] = parsestmts(p);
	n->csemi[0] = p->tok.loc;
	expect(p, POLY_TSEMI);
	if (p->tok.type != POLY_TSEMI)
		n->node[1] = parseexpr(p);
	n->csemi[1] = p->tok.loc;
	expect(p, POLY_TSEMI);
	if (p->tok.type != POLY_TRPAREN)
		n->node[2] = parsestmts(p);
	n->closing[0] = p->tok.loc;
	expect(p, POLY_TRPAREN);
	inloop = p->inloop;
	p->inloop = true;
	n->node[3] = parsestmt(p);
	p->inloop = inloop;
	return n;
}

static struct polynode *
parsestmt(struct polyparse *p)
{
	struct polynode *s;

	s = NULL;
	switch (p->tok.type) {
	case POLY_TLBRACE:
		s = parseblock(p);
		break;
	case POLY_TIDENT:
		s = parseident(p, 0);
		break;
	case POLY_TDO:
		s = parsedowhile(p);
		break;
	case POLY_TWHILE:
		s = parsewhile(p);
		break;
	case POLY_TFOR:
		s = parsefor(p);
		break;
	case POLY_TIF:
		s = parseif(p);
		break;
	case POLY_TINC:
	case POLY_TDEC:
		s = parseident(p, p->tok.type);
		break;
	case POLY_TBREAK:
		if (!p->inloop)
			parseerr(p, EINVAL, "break not in loop context");
		s = nod(p, POLY_ABREAK);
		nexttok(p);
		break;
	case POLY_TCONTINUE:
		if (!p->inloop)
			parseerr(p, EINVAL, "continue not in loop context");
		s = nod(p, POLY_ACONTINUE);
		nexttok(p);
		break;
	default:
		parseerr(p, EINVAL, "expected statement, got %s", polytoktypestr(p->tok.type));
		s = nod(p, POLY_ANONE);
		synctok(p, 's');
		break;
	}
	return s;
}

static struct polynode *
parsestmts(struct polyparse *p)
{
	struct polynode *h, **c;

	h = NULL;
	c = &h;
	while (tokattr(p->tok.type) & STMT) {
		*c = parsestmt(p);
		c = &((*c)->next);
	}
	return h;
}

static struct polynode *
parserun(struct polyparse *p)
{
	struct polynode *h, **c;

	h = NULL;
	c = &h;
	for (;;) {
		if (p->tok.type == POLY_TEOF)
			break;

		*c = parsestmt(p);
		(*c)->semi = p->tok.loc;
		expect(p, POLY_TSEMI);
		c = &((*c)->next);
	}
	return h;
}

void
polyparseaddbuiltins(struct polyparse *p, struct polyfunc *func, size_t nfunc)
{
	p->func = func;
	p->nfunc = nfunc;
}

int
polyparse(struct polyparse *p, struct polyast *a)
{
	memset(a, 0, sizeof(*a));
	p->ast = a;
	if (sigsetjmp(p->top, 0))
		return -1;
	a->name = pstrdup(p, p->scan.loc.name);
	nexttok(p);
	a->stmts = parserun(p);
	return 0;
}

void
polyparseclose(struct polyparse *p)
{
	polyscanclose(&p->scan);
}

void
polyastfree(struct polyast *a)
{
	struct polyblock *p, *q;

	for (p = a->arena; p; p = q) {
		q = p->next;
		free(p);
	}
}

static void
aprint(FILE *fp, int indent, const char *fmt, ...)
{
	static const int spaces = 2;

	va_list ap;
	int i, j;

	for (i = 0; i < indent; i++) {
		for (j = 0; j < spaces; j++)
			fprintf(fp, " ");
	}
	va_start(ap, fmt);
	vfprintf(fp, fmt, ap);
	va_end(ap);
}

static void
apnode(struct polyast *a, struct polynode *n, int indent, FILE *fp)
{
	struct polyloc *l;
	struct polynode *c;
	enum polytoktype t;
	void *pn;

	if (n == NULL || n->type == POLY_ANONE) {
		aprint(fp, indent, "<nil>\n");
		return;
	}

	pn = n;
	l = &n->loc;
	switch (n->type) {
	case POLY_ACOMMENT:
		aprint(fp, indent, "<comment> %p %zu:%zu \"%s\"\n", pn, l->line, l->col, n->sval);
		break;

	case POLY_AINCDEC:
		aprint(fp, indent++, "<incdec> %p <%zu:%zu> {\n", pn, l->line, l->col);
		aprint(fp, indent, "op <%zu:%zu>: %s", n->oploc.line, n->oploc.col, polytoktypestr(n->op));
		if (n->op == POLY_TPREINC || n->op == POLY_TPREDEC)
			fprintf(fp, " (pre)");
		else if (n->op == POLY_TPOSTINC || n->op == POLY_TPOSTDEC)
			fprintf(fp, " (post)");
		fprintf(fp, "\n");
		aprint(fp, indent, "name <%zu:%zu>: %s\n", n->nameloc.line, n->nameloc.col, n->name);
		aprint(fp, --indent, "}\n");
		break;

	case POLY_AASSIGN:
		aprint(fp, indent++, "<assign> %p <%zu:%zu> {\n", pn, l->line, l->col);
		aprint(fp, indent, "name %p <%zu:%zu>: %s\n", (void *)n->name, n->nameloc.line, n->nameloc.col, n->name);
		aprint(fp, indent, "op <%zu:%zu>: %s\n", n->oploc.line, n->oploc.col, polytoktypestr(n->op));
		aprint(fp, indent++, "value: {\n");
		apnode(a, n->node[0], indent, fp);
		aprint(fp, --indent, "}\n");
		aprint(fp, --indent, "}\n");
		break;

	case POLY_ASUB:
		aprint(fp, indent++, "<sub> %p <%zu:%zu> {\n", pn, l->line, l->col);
		for (c = n; c; c = c->node[1]) {
			aprint(fp, indent++, "[\n");
			aprint(fp, indent, "name %p <%zu:%zu>: %s\n", (void *)c->name, c->nameloc.line, c->nameloc.col, c->name);
			aprint(fp, indent, "op <%zu:%zu>: %s\n", c->oploc.line, c->oploc.col, polytoktypestr(c->op));
			apnode(a, c->node[0], indent, fp);
			aprint(fp, --indent, "]\n");
		}
		if (n->node[2]) {
			aprint(fp, indent++, "child: {\n");
			apnode(a, n->node[2], indent, fp);
			aprint(fp, --indent, "}\n");
		}
		aprint(fp, --indent, "}\n");
		break;

	case POLY_ACALL:
		aprint(fp, indent++, "<call> %p <%zu:%zu> {\n", pn, l->line, l->col);
		aprint(fp, indent, "arity: %d\n", n->arity);
		aprint(fp, indent, "name %p <%zu:%zu>: %s\n", (void *)n->name, n->nameloc.line, n->nameloc.col, n->name);
		aprint(fp, indent++, "args: {\n");
		for (c = n->arg; c; c = c->arg)
			apnode(a, c, indent, fp);
		aprint(fp, --indent, "}\n");

		aprint(fp, --indent, "}\n");
		break;

	case POLY_ABREAK:
	case POLY_ACONTINUE:
		t = (n->type == POLY_ABREAK) ? POLY_TBREAK : POLY_TCONTINUE;
		aprint(fp, indent, "<%s> %p <%zu:%zu>\n", polytoktypestr(t), pn, l->line, l->col);
		break;

	case POLY_AIF:
		aprint(fp, indent++, "<if> %p <%zu:%zu> {\n", pn, l->line, l->col);

		aprint(fp, indent++, "cond: {\n");
		apnode(a, n->node[0], indent, fp);
		aprint(fp, --indent, "}\n");

		aprint(fp, indent++, "body: {\n");
		apnode(a, n->node[1], indent, fp);
		aprint(fp, --indent, "}\n");

		if (n->node[2]) {
			aprint(fp, indent++, "else: {\n");
			apnode(a, n->node[2], indent, fp);
			aprint(fp, --indent, "}\n");
		}

		aprint(fp, --indent, "}\n");
		break;

	case POLY_ADOWHILE:
	case POLY_AWHILE:
		if (n->type == POLY_ADOWHILE)
			aprint(fp, indent++, "<dowhile> %p <%zu:%zu>{\n", pn, l->line, l->col);
		else
			aprint(fp, indent++, "<while> %p <%zu:%zu> {\n", pn, l->line, l->col);

		aprint(fp, indent++, "cond: {\n");
		apnode(a, n->node[0], indent, fp);
		aprint(fp, --indent, "}\n");

		aprint(fp, indent++, "body: {\n");
		apnode(a, n->node[1], indent, fp);
		aprint(fp, --indent, "}\n");
		break;

	case POLY_AFOR:
		aprint(fp, indent++, "<for> %p <%zu:%zu> {\n", pn, l->line, l->col);

		aprint(fp, indent++, "init: {\n");
		for (c = n->node[0]; c; c = c->next)
			apnode(a, c, indent, fp);
		aprint(fp, --indent, "}\n");

		aprint(fp, indent++, "cond: {\n");
		apnode(a, n->node[1], indent, fp);
		aprint(fp, --indent, "}\n");

		aprint(fp, indent++, "post: {\n");
		for (c = n->node[2]; c; c = c->next)
			apnode(a, c, indent, fp);
		aprint(fp, --indent, "}\n");

		aprint(fp, indent++, "body: {\n");
		apnode(a, n->node[3], indent, fp);
		aprint(fp, --indent, "}\n");

		aprint(fp, --indent, "}\n");
		break;

	case POLY_ABLOCK:
		aprint(fp, indent++, "<block> %p <%zu:%zu> {\n", pn, l->line, l->col);
		for (c = n->node[0]; c; c = c->next)
			apnode(a, c, indent, fp);
		aprint(fp, --indent, "}\n");
		break;

	case POLY_APAREN:
		aprint(fp, indent++, "<paren> %p <%zu:%zu> {\n", pn, l->line, l->col);
		apnode(a, n->node[0], indent, fp);
		aprint(fp, --indent, "}\n");
		break;

	case POLY_ANUMBER:
		aprint(fp, indent++, "<number> %p <%zu:%zu> %s\n", pn, l->line, l->col, n->sval);
		break;

	case POLY_AIDENT:
		aprint(fp, indent++, "<ident> %p <%zu:%zu> %s\n", pn, l->line, l->col, n->name);
		break;

	case POLY_ASTRING:
		aprint(fp, indent++, "<string> %p <%zu:%zu> %s\n", pn, l->line, l->col, n->sval);
		break;

	case POLY_ABINOP:
		aprint(fp, indent++, "<binop> %p <%zu:%zu> {\n", pn, l->line, l->col);
		aprint(fp, indent, "op <%zu:%zu>: %s\n", n->oploc.line, n->oploc.col, polytoktypestr(n->op));
		aprint(fp, indent++, "lhs: {\n");
		apnode(a, n->node[0], indent, fp);
		aprint(fp, --indent, "}\n");
		aprint(fp, indent++, "rhs: {\n");
		apnode(a, n->node[1], indent, fp);
		aprint(fp, --indent, "}\n");
		aprint(fp, --indent, "}\n");
		break;

	case POLY_AUNOP:
		aprint(fp, indent++, "<unop> %p <%zu:%zu> {\n", pn, l->line, l->col);
		aprint(fp, indent, "op <%zu:%zu>: %s\n", n->oploc.line, n->oploc.col, polytoktypestr(n->op));
		aprint(fp, ++indent, "value: {\n");
		apnode(a, n->node[0], indent, fp);
		aprint(fp, --indent, "}\n");
		aprint(fp, --indent, "}\n");
		break;

	default:
		aprint(fp, indent, "<unknown> %p <%zu:%zu> (%d)\n", pn, l->line, l->col, n->type);
		break;
	}
}

void
polyastvisitnode(struct polynode *n, polyvisitor_t f, void *ud)
{
	struct polynode *c;

	if (!f(n, ud))
		return;

	switch (n->type) {
	case POLY_AIF:
		polyastvisitnode(n->node[0], f, ud);
		polyastvisitnode(n->node[1], f, ud);
		if (n->node[2])
			polyastvisitnode(n->node[2], f, ud);
		break;
	case POLY_AWHILE:
	case POLY_ADOWHILE:
		polyastvisitnode(n->node[0], f, ud);
		polyastvisitnode(n->node[1], f, ud);
		break;
	case POLY_AFOR:
		polyastvisitnode(n->node[0], f, ud);
		polyastvisitnode(n->node[1], f, ud);
		polyastvisitnode(n->node[2], f, ud);
		polyastvisitnode(n->node[3], f, ud);
		break;
	case POLY_ABLOCK:
		for (c = n->node[0]; c; c = c->next)
			polyastvisitnode(c, f, ud);
		break;
	case POLY_AASSIGN:
		polyastvisitnode(n->node[0], f, ud);
		break;
	case POLY_ACALL:
		for (c = n->arg; c; c = c->arg)
			polyastvisitnode(c, f, ud);
		break;
	case POLY_ASUB:
		for (c = n; c; c = c->node[1])
			polyastvisitnode(c->node[0], f, ud);
		if (n->node[2])
			polyastvisitnode(n->node[2], f, ud);
		break;
	case POLY_APAREN:
		polyastvisitnode(n->node[0], f, ud);
		break;
	case POLY_ABINOP:
		polyastvisitnode(n->node[0], f, ud);
		polyastvisitnode(n->node[1], f, ud);
		break;
	case POLY_AUNOP:
		polyastvisitnode(n->node[0], f, ud);
		break;
	default:
		break;
	}

	polyastvisitnode(NULL, f, ud);
}

void
polyastprint(struct polyast *a, FILE *fp)
{
	struct polynode *s;

	fprintf(fp, "AST Tree Size: %zu bytes\n\n", a->arenasize);
	if (a->comhead) {
		fprintf(fp, "<comments> {\n");
		for (s = a->comhead; s; s = s->next)
			apnode(a, s, 1, fp);
		fprintf(fp, "}\n");
	}
	for (s = a->stmts; s; s = s->next)
		apnode(a, s, 0, fp);
}

struct polyfunc *
polydefbuiltins(size_t *nfunc)
{
	static struct polyfunc funcs[] = {
	    {"print", NULL, -1, false},
	    {"int", NULL, 2, true},
	    {"diff", NULL, 2, true},
	    {"deg", NULL, 2, true},
	    {"coef", NULL, 2, false},
	};
	*nfunc = nelem(funcs);
	return funcs;
}

void
polyprintinit(struct polyprint *p, struct polyfmt *f, FILE *fp)
{
	memset(p, 0, sizeof(*p));
	p->fmt = *f;
	p->fp = fp;
	p->tw = (struct polytabwriter){
	    .fp = fp,
	    .tabstop = f->tabstop,
	    .spaces = f->spaces,
	};
}

static void
prindent(struct polyprint *p, size_t indent, size_t cols)
{
	size_t i;

	for (i = 0; i < indent; i++)
		polytwputs(&p->tw, "\t");
	for (i = 0; i < cols; i++)
		polytwputs(&p->tw, " ");
}

static size_t
prcombefore(struct polyprint *p, struct polyloc *loc)
{
	struct polynode *com;
	struct polyloc ploc;
	size_t ncom;

	ploc.line = 0;
	com = p->com;
	ncom = 0;
	while (com) {
		if (loc && polyloccmp(&com->loc, loc) > 0)
			break;
		if (ploc.line && ploc.line + 1 != com->loc.line)
			polytwputs(&p->tw, "\n");

		if (loc && loc->line != com->loc.line)
			prindent(p, p->ind, p->col);
		else if (loc)
			polytwputs(&p->tw, " ");

		polytwputsln(&p->tw, com->sval);

		ploc = com->loc;
		com = com->next;
		ncom++;
	}
	p->com = com;

	if (loc && ploc.line && ploc.line + 1 < loc->line && loc->line != SIZE_MAX)
		polytwputs(&p->tw, "\n");

	return ncom;
}

static ssize_t
combetween(struct polyprint *p, struct polyloc *l0, struct polyloc *l1)
{
	struct polyloc *lp;

	if (!p->com)
		return -1;
	lp = &p->com->loc;
	if (!(polyloccmp(lp, l0) > 0 && polyloccmp(lp, l1) < 0))
		return -1;
	return lp->line - l0->line;
}

static bool
prcomafter(struct polyprint *p, struct polyloc *l0, struct polyloc *l1)
{
	ssize_t nc;

	nc = combetween(p, l0, l1);
	if (nc < 0)
		return false;

	// if the closest comment is on the same line
	// print out that comment with no newline in between
	// we handle the printing out of the newlines after this
	if (nc == 0) {
		polytwputs(&p->tw, " ");
		polytwputs(&p->tw, p->com->sval);
		p->com = p->com->next;
	}

	// now we calculate the next comment distance from
	// our current node, if the distance is more than one line
	// print out an extra newline to signify that since
	// prcombefore only sees the first comment as beginning
	// of the text (it doesn't know anything about before it)
	nc = combetween(p, l0, l1);
	if (nc < 0)
		polytwputs(&p->tw, "\n");
	if (nc > 0)
		polytwputs(&p->tw, "\n");
	if (nc > 1)
		polytwputs(&p->tw, "\n");

	prcombefore(p, l1);
	return nc > 0;
}

static void
proutput(struct polyprint *p)
{
	struct polyloc *l0, *l1;
	int a0, a1;
	const char *lit;
	ssize_t nc;
	size_t wn;
	bool ac;

	if (p->looklen == 0)
		return;

	lit = p->look[0].lit;
	l0 = p->look[0].loc;
	l1 = p->look[1].loc;
	a0 = p->look[0].attr;
	a1 = p->look[1].attr;

	// update our current location
	if (l0 && l1)
		assert(polyloccmp(l0, l1) <= 0);
	p->loc = l0;
	if (l1)
		p->loc = l1;

	// print all comments before the current node
	prcombefore(p, l0);

	// encountered eof
	if (l0->line == SIZE_MAX)
		return;

	// need a lookahead token in order to print properly
	if (p->looklen < 2)
		return;

	// find out how far the closest comment to l0 is, if there is any
	// this is used to figure out if we need to suppress printing
	// spaces or newlines
	nc = combetween(p, l0, l1);

	// if we are indenting, indent the current indentation level
	if (a0 & INDENT)
		prindent(p, p->ind, 0);
	// pad with spaces, for alignment
	else if (a0 & PADSPACES)
		prindent(p, 0, (a0 >> 16) & 0xff);
	// if this is a newline, we need to check if there is a comment at the end,
	// and let the comment printing code handle the newline for us if there is
	else if ((a0 & NEWLINE) && nc < 0)
		polytwputs(&p->tw, "\n");
	// new scope, increase indentation level
	else if (a0 & SCOPE) {
		p->ind++;
		if (nc < 0)
			polytwputs(&p->tw, "\n");
	}
	// end scope, decrease indentation level
	else if (a0 & UNSCOPE)
		prindent(p, --p->ind, 0);
	// otherwise we are printing a literal
	else if (lit) {
		if (a0 & LEADSPACE)
			polytwputs(&p->tw, " ");

		wn = polytwputs(&p->tw, lit);
		// statements increases the current column offset
		// but expressions don't because we want to align
		// with the statements, not to the expression
		if (a0 & STMT)
			p->col += wn;

		// if there is a trailing space and there is a comment on the current node
		// make sure there is not on the same line so we don't print extra space
		if (a0 & TRAILSPACE) {
			if (nc != 0)
				polytwputs(&p->tw, " ");
			if (a0 & STMT)
				p->col++;
		}
	}

	// print all the comments from current node to next node
	// including comments on the same line as current node
	ac = prcomafter(p, l0, l1);

	// if we are an expression or a statement and the next node is on a different
	// line, we need to insert a newline manually since only statements insert
	// a newline after they are printed
	if ((a0 & (EXPR | STMT)) && !((a0 & MERGELINE) && !ac) && l0->line < l1->line) {
		// printing out comments handle newlines for us so we don't need to if there was a comment
		// otherwise, we need to insert a newline
		if (nc < 0) {
			polytwputs(&p->tw, "\n");

			// if the next node is more than one line away, we print another newline
			// to signify that
			if (l0->line + 1 < l1->line)
				polytwputs(&p->tw, "\n");
		}
		// print an indent to align the next expression
		// if the next node has an expression no alignment
		// we need to reset column immediately (this is for '{' characters)
		if (a1 & NOINDENTCOL)
			p->col = 0;
		prindent(p, p->ind, p->col);
	}

	p->look[0] = p->look[1];
	p->looklen = 1;
}

static void
praddnode(struct polyprint *p, struct polyloc *loc, int attr, const char *lit)
{
	p->look[p->looklen].loc = loc;
	p->look[p->looklen].attr = attr;
	p->look[p->looklen].lit = lit;
	p->looklen++;
	proutput(p);
}

static void
prexpr(struct polyprint *p, struct polynode *n)
{
	struct polynode *c;
	int at;

	switch (n->type) {
	case POLY_AIDENT:
		praddnode(p, &n->loc, EXPR, n->name);
		break;
	case POLY_ANUMBER:
		praddnode(p, &n->loc, EXPR, n->sval);
		break;
	case POLY_ACALL:
		if (n->opening[0].line) {
			praddnode(p, &n->loc, EXPR, n->name);
			praddnode(p, &n->opening[0], EXPR, "(");
		} else
			praddnode(p, &n->loc, EXPR | TRAILSPACE, n->name);
		for (c = n->arg; c; c = c->arg) {
			prexpr(p, c);
			if (c->comma.line)
				praddnode(p, &c->comma, EXPR | TRAILSPACE, ",");
		}
		if (n->closing[0].line)
			praddnode(p, &n->closing[0], EXPR, ")");
		break;
	case POLY_ABINOP:
		prexpr(p, n->node[0]);
		// by default a binary operator will have a separating space
		// like so <lhs> <op> <rhs>, however, if the <lhs> had a newline
		// we can't print a leading space since it is at the beginning of
		// an operator
		at = EXPR | TRAILSPACE;
		if (p->loc && p->loc->line == n->oploc.line)
			at |= LEADSPACE;
		praddnode(p, &n->oploc, at, polytoktypestr(n->op));
		prexpr(p, n->node[1]);
		break;
	case POLY_AUNOP:
		praddnode(p, &n->oploc, EXPR, polytoktypestr(n->op));
		prexpr(p, n->node[0]);
		break;
	case POLY_APAREN:
		praddnode(p, &n->opening[0], EXPR, "(");
		prexpr(p, n->node[0]);
		praddnode(p, &n->closing[0], EXPR, ")");
		break;
	case POLY_ASUB:
		if (n->node[2])
			prexpr(p, n->node[2]);
		praddnode(p, &n->opening[0], EXPR, "[");
		for (c = n; c; c = c->node[1]) {
			praddnode(p, &c->nameloc, EXPR | TRAILSPACE, c->name);
			praddnode(p, &c->oploc, EXPR | TRAILSPACE, polytoktypestr(c->op));
			prexpr(p, c->node[0]);
			if (c->comma.line)
				praddnode(p, &c->comma, EXPR | TRAILSPACE, ",");
		}
		praddnode(p, &n->closing[0], EXPR, "]");
		break;
	default:
		assert(0);
		break;
	}
}

static void
prfor(struct polyprint *p, struct polynode *n)
{
	struct polynode *c;
	int padws;

	praddnode(p, &n->loc, STMT | TRAILSPACE, "for");
	praddnode(p, &n->opening[0], STMT, "(");
	padws = 5;

	for (c = n->node[0]; c; c = c->next) {
		prstmt(p, c, true, false, c->next != NULL);
		if (c->next) {
			praddnode(p, p->loc, INDENT, NULL);
			praddnode(p, p->loc, PADSPACES | (padws << 16), NULL);
		}
	}
	praddnode(p, &n->csemi[0], STMT | TRAILSPACE, ";");

	prexpr(p, n->node[1]);
	praddnode(p, &n->csemi[1], STMT | TRAILSPACE, ";");

	for (c = n->node[2]; c; c = c->next) {
		prstmt(p, c, true, false, c->next != NULL);
		if (c->next) {
			praddnode(p, p->loc, INDENT, NULL);
			praddnode(p, p->loc, PADSPACES | (padws << 16), NULL);
		}
	}

	if (p->fmt.style == POLY_SALLMAN) {
		praddnode(p, &n->closing[0], STMT, ")");
		if (n->node[3]->type == POLY_ABLOCK)
			praddnode(p, &n->closing[0], NEWLINE, NULL);
		praddnode(p, &n->closing[0], INDENT, NULL);
	} else
		praddnode(p, &n->closing[0], STMT | MERGELINE | TRAILSPACE, ")");

	prctrlblock(p, n->node[3], false);
}

static void
prctrlcond(struct polyprint *p,
           struct polyloc *loc,
           struct polyloc *opening,
           struct polyloc *closing,
           const char *pre,
           struct polynode *expr,
           struct polynode *stmt,
           int endspace)
{
	praddnode(p, loc, STMT | TRAILSPACE, pre);
	praddnode(p, opening, STMT, "(");
	prexpr(p, expr);
	if (p->fmt.style == POLY_SALLMAN) {
		praddnode(p, closing, STMT, ")");
		if (stmt && stmt->type == POLY_ABLOCK)
			praddnode(p, closing, NEWLINE, NULL);
		praddnode(p, closing, INDENT, NULL);
	} else
		praddnode(p, closing, STMT | MERGELINE | endspace, ")");
}

static void
prctrlblock(struct polyprint *p, struct polynode *b, bool mcb)
{
	struct polynode *c;

	if (b->type == POLY_ABLOCK)
		praddnode(p, &b->opening[0], STMT | NOINDENTCOL, "{");
	praddnode(p, p->loc, SCOPE, NULL);

	if (b->type == POLY_ABLOCK) {
		for (c = b->node[0]; c; c = c->next)
			prstmt(p, c, true, true, true);
	} else
		prstmt(p, b, true, true, false);

	if (b->type == POLY_ABLOCK) {
		praddnode(p, &b->closing[0], UNSCOPE, NULL);
		praddnode(p, &b->closing[0], STMT | (mcb) ? MERGELINE : 0, "}");
	} else
		praddnode(p, p->loc, UNSCOPE, NULL);
}

static void
prstmt(struct polyprint *p, struct polynode *n, bool zc, bool ind, bool nl)
{
	struct polynode *c;

	// each statement resets the column offset
	if (zc)
		p->col = 0;

	// all statements start with an indent except in control statements
	if (ind) {
		// if there exist a statement before this statement
		// see if they are separated by more than one line
		// if they are, we need to insert a newline to show that
		if (p->loc && p->loc->line + 1 < n->loc.line)
			praddnode(p, &n->loc, NEWLINE, NULL);
		praddnode(p, &n->loc, INDENT, NULL);
	}

	switch (n->type) {
	case POLY_AASSIGN:
		praddnode(p, &n->nameloc, STMT | TRAILSPACE, n->name);
		praddnode(p, &n->oploc, STMT | TRAILSPACE, polytoktypestr(n->op));
		prexpr(p, n->node[0]);
		break;
	case POLY_AINCDEC:
		if (n->op == POLY_TPREINC || n->op == POLY_TPREDEC) {
			praddnode(p, &n->oploc, STMT, polytoktypestr(n->op));
			praddnode(p, &n->nameloc, STMT, n->name);
		} else {
			praddnode(p, &n->nameloc, STMT, n->name);
			praddnode(p, &n->oploc, STMT, polytoktypestr(n->op));
		}
		break;
	case POLY_ABLOCK:
		praddnode(p, &n->opening[0], STMT, "{");
		praddnode(p, &n->opening[0], SCOPE, NULL);
		for (c = n->node[0]; c; c = c->next)
			prstmt(p, c, true, true, true);
		praddnode(p, &n->closing[0], UNSCOPE, NULL);
		praddnode(p, &n->closing[0], STMT, "}");
		break;
	case POLY_AIF:
		prctrlcond(p, &n->loc, &n->opening[0], &n->closing[0], "if", n->node[0], n->node[1], TRAILSPACE);
		prctrlblock(p, n->node[1], n->node[2] != NULL);
		if (n->node[2]) {
			if (p->fmt.style == POLY_SALLMAN) {
				praddnode(p, &n->elseloc, NEWLINE, NULL);
				praddnode(p, &n->elseloc, INDENT, NULL);
				praddnode(p, &n->elseloc, STMT, "else");
				praddnode(p, &n->elseloc, NEWLINE, NULL);
				praddnode(p, &n->elseloc, INDENT, NULL);
			} else
				praddnode(p, &n->elseloc, LEADSPACE | STMT | TRAILSPACE, "else");
			prctrlblock(p, n->node[2], false);
		}
		break;
	case POLY_AWHILE:
		prctrlcond(p, &n->loc, &n->opening[0], &n->closing[0], "while", n->node[0], n->node[1], TRAILSPACE);
		prctrlblock(p, n->node[1], false);
		break;
	case POLY_ADOWHILE:
		praddnode(p, &n->loc, STMT | TRAILSPACE, "do");
		if (p->fmt.style == POLY_SALLMAN) {
			if (n->node[0]->type == POLY_ABLOCK)
				praddnode(p, p->loc, NEWLINE, NULL);
		}
		prctrlblock(p, n->node[0], false);
		praddnode(p, p->loc, STMT | TRAILSPACE, "");
		prctrlcond(p, &n->whileloc, &n->opening[0], &n->closing[0], "while", n->node[1], NULL, 0);
		break;
	case POLY_AFOR:
		prfor(p, n);
		break;
	case POLY_ACALL:
		if (n->opening[0].line) {
			praddnode(p, &n->nameloc, STMT, n->name);
			praddnode(p, &n->opening[0], STMT, "(");
		} else
			praddnode(p, &n->nameloc, STMT | TRAILSPACE, n->name);
		for (c = n->arg; c; c = c->arg) {
			prexpr(p, c);
			if (c->comma.line)
				praddnode(p, &c->comma, STMT | TRAILSPACE, ",");
		}
		if (n->closing[0].line)
			praddnode(p, &n->closing[0], STMT, ")");
		break;
	default:
		assert(0);
		break;
	}

	if (n->semi.line)
		praddnode(p, &n->semi, STMT, ";");

	// end of statement always contain a newline
	// this means we split statements up on their own lines
	if (nl)
		praddnode(p, p->loc, NEWLINE, NULL);

	// need to reset the column at the end in the case
	// if there are comments after all the statements so
	// we can flush them out correctly
	if (zc)
		p->col = 0;
}

void
polyprintast(struct polyprint *p, struct polyast *a)
{
	struct polyloc eof;
	struct polynode *c;

	eof = (struct polyloc){.line = SIZE_MAX};
	p->loc = NULL;
	p->looklen = 0;
	p->com = a->comhead;
	for (c = a->stmts; c; c = c->next)
		prstmt(p, c, true, true, true);
	praddnode(p, &eof, 0, NULL);
	proutput(p);
	polytwflush(&p->tw);
}

int
polyevaltree(struct polystate *e, struct polyast *a)
{
	struct polynode *c;
	int rv;

	for (c = a->stmts; c; c = c->next) {
		if ((rv = polyevalnode(e, c)))
			break;
	}
	return rv;
}

int
polyevalnode(struct polystate *e, struct polynode *n)
{
	return 0;
}

static long
gcd(long a, long b)
{
	if (a < 0)
		a = -a;
	if (b < 0)
		b = -b;
	while (b != 0) {
		a %= b;
		if (a == 0)
			return b;
		b %= a;
	}
	return a;
}

static long
lcm(long a, long b)
{
	return (a * b) / gcd(a, b);
}

int
polynuminitstr(struct polynum *p, const char *s)
{
	double v;

	sscanf(s, "%lf", &v);
	p->n = v;
	p->d = 1;
	return 0;
}

char *
polynumstr(struct polynum *p, char *b, size_t n)
{
	if (p->d != 1)
		snprintf(b, n, "%ld/%ld", p->n, p->d);
	else
		snprintf(b, n, "%ld", p->n);
	return b;
}

void
polynumcanon(struct polynum *r)
{
	long m;

	m = gcd(r->n, r->d);
	r->n /= m;
	r->d /= m;
}

void
polynumadd(struct polynum *r, struct polynum *x, struct polynum *y)
{
	struct polynum a, b;
	long m;

	m = lcm(x->d, y->d);
	a = (struct polynum){x->n * m / x->d, m};
	b = (struct polynum){y->n * m / y->d, m};
	*r = (struct polynum){a.n + b.n, m};
	polynumcanon(r);
}

void
polynumsub(struct polynum *r, struct polynum *x, struct polynum *y)
{
	struct polynum a, b;
	long m;

	m = lcm(x->d, y->d);
	a = (struct polynum){x->n * m / x->d, m};
	b = (struct polynum){y->n * m / y->d, m};
	*r = (struct polynum){a.n - b.n, m};
	polynumcanon(r);
}

void
polynummul(struct polynum *r, struct polynum *x, struct polynum *y)
{
	r->n = x->n * y->n;
	r->d = x->d * y->d;
	polynumcanon(r);
}

void
polynumdiv(struct polynum *r, struct polynum *x, struct polynum *y)
{
	r->n = x->n * y->d;
	r->d = x->d * y->n;
	polynumcanon(r);
}

void
polynumexp(struct polynum *r, struct polynum *x, struct polynum *y)
{
	long double e;

	e = y->n * 1.0L / y->d;
	r->n = powl(x->n, e);
	r->d = powl(x->d, e);
	polynumcanon(r);
}

size_t
polytwputs(struct polytabwriter *w, const char *s)
{
	size_t i;

	for (i = 0; s[i]; i++)
		polytwputc(w, s[i]);
	return i;
}

size_t
polytwputsln(struct polytabwriter *w, const char *s)
{
	size_t n;
	n = polytwputs(w, s);
	n += polytwputc(w, '\n');
	return n;
}

size_t
polytwputc(struct polytabwriter *w, char c)
{
	size_t i, n;

	if (c == '\n')
		w->pos = 0;
	if (c == '\t') {
		if (w->spaces) {
			n = (w->tabstop - w->pos) % w->tabstop;
			if (n == 0)
				n = w->tabstop;
			for (i = 0; i <= n; i++)
				fprintf(w->fp, " ");
		} else
			fprintf(w->fp, "\t");
		w->pos = 0;
	} else {
		fprintf(w->fp, "%c", c);
		w->pos++;
	}
	w->lastch = c;
	return 1;
}

void
polytwflush(struct polytabwriter *w)
{
	if (w->lastch != '\n') {
		fprintf(w->fp, "\n");
		w->lastch = '\n';
	}
	fflush(w->fp);
}
