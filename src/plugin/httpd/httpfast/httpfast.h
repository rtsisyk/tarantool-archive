#ifndef _GNU_SOURCE
	#define _GNU_SOURCE
#endif
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <time.h>
#include <stdlib.h>

typedef struct {
	char   *str;
	size_t  len;
} str_t;

typedef struct {
	str_t name;
	str_t val;
} header_t;

typedef union {
	uint32_t            *i;
	char                *c;
	unsigned char       *uc;
	
	const uint32_t      *ci;
	
	const unsigned char *ucc;
	const char          *cc;
} uniptr;

typedef enum {
		start = 0,
		
		method,
		path,
		protocol,
		
		version,
		version_minor,
		status_sp,
		status,
		message_sp,
		message,
		message_end,
		cr,
		lf,
		header_next,
		header_name,
		header_sp,
		header_cl,
		header_cl_sp,
		header_val,
		header_cr,
		header_lf,
		header_last_cr,
		header_last_lf,
		skip_line
} parser_state;

typedef enum {
		hd_other = 0,
		hd_connection,
		hd_clength,
		hd_tr_encoding
} http_header;


typedef struct {
	char     *p;
	char     *e;
	header_t  *headers;
	size_t     header_i;
	size_t     header_max;
	parser_state state; // enum
	
	//for all
	struct {
		int major;
		int minor;
	} version;
	str_t      reason;
	
	// for response
	int        status;
	
	// for request
	str_t      path;
	size_t     clength;
	
} parse_http_state;

int parse_http_request(parse_http_state * s);

int parse_http_response_line(parse_http_state * s);
int parse_http_headers(parse_http_state * s);

