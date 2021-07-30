#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include "poly.h"

int fflag = 0;
int lflag = 0;
int Tflag = 0;
int wflag = 0;
int sflag = POLY_SKR;
int uflag = 0;

void
fatal(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "\n");
	exit(1);
}

void
usage(void)
{
	fprintf(stderr, "usage: poly [options] file\n");
	fprintf(stderr, "  -f            format the source file\n");
	fprintf(stderr, "  -l            lex only\n");
	fprintf(stderr, "  -h            show this message\n");
	fprintf(stderr, "  -T <detail>   print ast tree\n");
	fprintf(stderr, "  -s <style>    use format style (default: kr)\n");
	fprintf(stderr, "  -u <tabstop>  set number of spaces per tab (default: tabs)\n");
	fprintf(stderr, "  -w            write result to source file instead of stdout\n");
	fprintf(stderr, "\navailable styles: allman kr\n");
	exit(2);
}

void
parseargs(int *argc, char **argv[])
{
	int i, j, skip;

	for (i = 1; i < *argc; i++) {
		if ((*argv)[i][0] != '-')
			break;
		if ((*argv)[i][1] == '-')
			break;

		skip = 0;
		for (j = 1; (*argv)[i][j]; j++) {
			switch ((*argv)[i][j]) {
			case 'f':
				fflag = 1;
				break;
			case 'l':
				lflag = 1;
				break;
			case 'T':
				if (i + skip + 1 >= *argc)
					usage();
				Tflag = atoi((*argv)[i + skip + 1]);
				if (Tflag <= 0)
					usage();
				skip++;
				break;
			case 's':
				if (i + skip + 1 >= *argc)
					usage();
				if (!strcasecmp((*argv)[i + skip + 1], "kr"))
					sflag = POLY_SKR;
				else if (!strcasecmp((*argv)[i + skip + 1], "allman"))
					sflag = POLY_SALLMAN;
				else
					usage();
				skip++;
				break;
			case 'u':
				if (i + skip + 1 >= *argc)
					usage();
				uflag = atoi((*argv)[i + skip + 1]);
				skip++;
				break;
			case 'w':
				wflag = 1;
				break;
			case 'h':
				usage();
				break;
			default:
				fprintf(stderr, "unknown option '%c'\n", (*argv)[i][j]);
				usage();
				break;
			}
		}
		i += skip;
	}
	*argc -= i;
	*argv += i;
	if (*argc >= 2)
		usage();
}

void
printtok(struct polyscan *s, struct polytok *t, int err, const char *msg, void *u)
{
	printf("%s:%zu:%zu: ", t->loc.name, t->loc.line, t->loc.col);
	if (err)
		printf("%s", msg);
	else {
		printf("%s", polytoktypestr(t->type));
		switch (t->type) {
		case POLY_TSTRING:
		case POLY_TNUMBER:
		case POLY_TIDENT:
		case POLY_TCOMMENT:
			printf(" %s", t->lit);
			break;
		default:
			break;
		}
	}
	printf("\n");
	(void)s;
	(void)u;
}

FILE *
xfopen(const char *name, const char *mode)
{
	FILE *fp;

	fp = fopen(name, mode);
	if (!fp)
		fatal("%s: %s", name, strerror(errno));
	return fp;
}

void
dumptoks(const char *name)
{
	struct polyscan scan;
	struct polytok tok;
	FILE *fp;
	int rv;

	fp = xfopen(name, "rt");
	if ((rv = polyscanfile(&scan, name, fp, printtok, NULL)) < 0)
		fatal("%s: %s", name, strerror(-rv));
	for (;;) {
		polyscan(&scan, &tok);
		if (tok.type == POLY_TEOF)
			break;
		printtok(&scan, &tok, 0, NULL, NULL);
	}
	polyscanclose(&scan);
	fclose(fp);
}

void
errparse(struct polyparse *p, int err, const char *msg, void *u)
{
	struct polytok *t;
	size_t maxerrs;

	t = &p->tok;
	fprintf(stderr, "%s:%zu:%zu: %s\n", t->loc.name, t->loc.line, t->loc.col, msg);
	if (u) {
		maxerrs = *(size_t *)u;
		if (p->nerr >= maxerrs)
			fatal("encountered too many errors! aborting!");
	}
	(void)err;
}

void
dumpast(const char *name, int detail)
{
	struct polyparse parser;
	struct polyast ast;
	int mode, rv;
	FILE *fp;

	if (detail <= 0)
		detail = 1;

	mode = 0;
	if (detail >= 2)
		mode |= POLY_PDECL;

	fp = xfopen(name, "rt");
	if ((rv = polyparsefile(&parser, name, fp, errparse, NULL, mode) < 0))
		fatal("%s: %s", name, strerror(-rv));

	polyparse(&parser, &ast);
	polyparseclose(&parser);
	if (parser.nerr == 0)
		polyastprint(&ast, stdout);
	polyastfree(&ast);
	fclose(fp);
}

int
writefile(const char *name, FILE *ifp)
{
	FILE *ofp;
	char buf[BUFSIZ];
	size_t nr;

	ofp = fopen(name, "wt");
	if (!ofp)
		return -errno;

	for (;;) {
		nr = fread(buf, 1, sizeof(buf), ifp);
		if (nr == 0)
			break;
		fwrite(buf, 1, nr, ofp);
	}

	if (fclose(ofp))
		return -errno;

	return 0;
}

void
formatsrc(const char *name)
{
	struct polyfmt fmt;
	struct polyparse parser;
	struct polyast ast;
	struct polyprint printer;
	FILE *ifp, *ofp;
	size_t maxerrs;
	int rv;

	maxerrs = 10;
	fmt = (struct polyfmt){
	    .style = sflag,
	    .spaces = false,
	};
	if (uflag > 0) {
		fmt.spaces = true;
		fmt.tabstop = uflag;
	}
	ofp = stdout;
	if (wflag) {
		ofp = tmpfile();
		if (!ofp)
			fatal("%s: failed to create temp file for formatting: %s\n", name, strerror(errno));
	}
	polyprintinit(&printer, &fmt, ofp);

	ifp = xfopen(name, "rt");
	if ((rv = polyparsefile(&parser, name, ifp, errparse, &maxerrs, 0) < 0))
		fatal("%s: %s", name, strerror(-rv));

	polyparse(&parser, &ast);
	polyparseclose(&parser);
	if (parser.nerr == 0)
		polyprintast(&printer, &ast);
	polyastfree(&ast);
	fclose(ifp);
	if (wflag) {
		if (ferror(ofp))
			fatal("%s: i/o error during formatting: %s", name, strerror(errno));
		fseek(ofp, 0, SEEK_SET);
		writefile(name, ofp);
		fclose(ofp);
	}
}

void
repl(void)
{
}

void
run(const char *name)
{
	struct polystate ctx;
	struct polyparse parser;
	struct polyast ast;
	FILE *fp;
	size_t maxerrs;
	int rv;

	maxerrs = 10;
	fp = xfopen(name, "rt");
	if ((rv = polyparsefile(&parser, name, fp, errparse, &maxerrs, POLY_PDECL) < 0))
		fatal("%s: %s", name, strerror(-rv));

	polyparse(&parser, &ast);
	if (parser.nerr == 0)
		polyevaltree(&ctx, &ast);
	polyparseclose(&parser);
	polyastfree(&ast);
	fclose(fp);
}

int
main(int argc, char *argv[])
{
	parseargs(&argc, &argv);

	if (argc < 1 && (fflag | lflag | Tflag))
		usage();

	if (lflag)
		dumptoks(argv[0]);
	else if (Tflag)
		dumpast(argv[0], Tflag);
	else if (fflag)
		formatsrc(argv[0]);
	if (fflag | lflag | Tflag)
		return 0;

	if (argc < 1)
		repl();
	else
		run(argv[0]);
	return 0;
}
