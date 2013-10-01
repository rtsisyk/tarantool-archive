#include "httpfast.h"
#include <errno.h>

#ifndef likely
#define likely(x) __builtin_expect((x),1)
#define unlikely(x) __builtin_expect((x),0)
#endif

#define TAB    (char)  9
#define LF     (char) 10
#define CR     (char) 13
#define CRLF   "\x0d\x0a"

//#define MYDEBUG
#ifdef MYDEBUG
#define WHERESTR    " at %s line %d.\n"
#define WHEREARG    __FILE__, __LINE__
#define debug(fmt, ...)   do{ \
	fprintf(stderr, "%s:%d: ", __FILE__, __LINE__); \
	fprintf(stderr, fmt, ##__VA_ARGS__); \
	if (fmt[strlen(fmt) - 1] != CR) { fprintf(stderr, "\n"); } \
	} while(0)
#else
#define debug(...)
#endif

#define cwarn(fmt, ...)   do{ \
	fprintf(stderr, "[WARN] %s:%d: ", __FILE__, __LINE__); \
	fprintf(stderr, fmt, ##__VA_ARGS__); \
	if (fmt[strlen(fmt) - 1] != LF) { fprintf(stderr, "\n"); } \
	} while(0)



static char lowcase[] =
	"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
	"\0\0\0\0\0\0\0\0\0\0\0\0\0-\0\0" "0123456789\0\0\0\0\0\0"
	"\0abcdefghijklmnopqrstuvwxyz\0\0\0\0_"
	"\0abcdefghijklmnopqrstuvwxyz\0\0\0\0\0"
	"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
	"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
	"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
	"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";

static const uint32_t HTTP = 'H' | ('T'<<8) | ( 'T' << 16 ) | ( 'P' << 24 );
static const uint32_t v_11 = '/' | ('1'<<8) | ( '.' << 16 ) | ( '1' << 24 );
static const uint32_t v_10 = '/' | ('1'<<8) | ( '.' << 16 ) | ( '0' << 24 );
static const uint32_t v_09 = '/' | ('0'<<8) | ( '.' << 16 ) | ( '9' << 24 );

int parse_http_request_line(parse_http_state * s) {
	// METHOD PATH PROTO \r? \n
	(void)s;
	return 0;
}

int parse_http_response_line(parse_http_state * s) {
	register uniptr  p           = (uniptr) s->p;      // main pointer
	register char   *e           = s->e;      // end of buffer
	
	char *ptr;
	char err[256];err[0] = 0;
	
#define myerror(msg, ...) do {\
	snprintf(err,256,msg " at %s line %d\n", ##__VA_ARGS__, __FILE__, __LINE__); \
	fprintf(stderr, msg " at %s line %d\n", ##__VA_ARGS__, __FILE__, __LINE__); \
	goto error; \
} while(0)
	
	// need: HTTP/x.x XXX ?\r?\n
	//       4   4   4   2  2
	if (unlikely( s->state >= header_next ))
		return s->version.minor + s->version.major * 10;
	
	switch (s->state) {
		case start:
			if (unlikely( e - p.c < 16 )) goto shortread;
			if( *p.i++ == HTTP ) {
				s->state = version;
			} else {
				myerror("HTTP expected");
			}
			//no break;
		case version:
			if( likely( *p.i == v_11 ) ) {
				s->version.minor = s->version.major = 1;
			}
			else
			if( *p.i == v_10 ) {
				s->version.major = 1;
			}
			else
			if( *p.i == v_09 ) {
				s->version.minor = 9;
			}
			else {
				myerror("bad version?");
			}
			p.i++;
			s->state = status;
			//no break;
		case status:
			s->status = strtol( p.c, &ptr, 10 );
			if (!s->status || ( ptr - p.c ) == 0) {
				myerror("Bad status");
			}
			s->state = message;
			//no break;
		case message:
			for(; *p.c == ' ' || *p.c == TAB;p.c++);
			if (unlikely( *p.c == 0 ) ) goto shortread;
			s->reason.str = p.c;
			s->state = message_end;
			//no break;
		case message_end:
			p.c = ptr = strchrnul(p.c, LF);
			if (unlikely( *p.c == 0 ) ) goto shortread;
			if (*(ptr-1) == CR) ptr--;
			s->reason.len = ptr - s->reason.str;
			p.c++;
			s->state = header_next;
			break;
		default:
			break;
	}
	
	//cwarn("next: >%-.10s...", p.c);
	s->p = p.c;
	return s->version.minor + s->version.major * 10;
	
	shortread:
		debug("not enough data");
		s->p = p.c;
		return -1;
	error:
		debug("parse error: %s", err);
		//call_error(r, newSVpvf("HTTP headers parse error: %s",err));
		errno = EINVAL;
		return 0;
	
}

int parse_http_headers(parse_http_state * s) {
	register parser_state  state = s->state;  // state of parsing
	register uniptr  p           = (uniptr) s->p;      // main pointer
	register char   *e           = s->e;      // end of buffer
	register unsigned char c;                 // current char
	
	char *ptr;
	char err[256];err[0] = 0;
	
#define myerror(msg, ...) do {\
	snprintf(err,256,msg " at %s line %d\n", ##__VA_ARGS__, __FILE__, __LINE__); \
	fprintf(stderr, msg " at %s line %d\n", ##__VA_ARGS__, __FILE__, __LINE__); \
	goto error; \
} while(0)
	
	for (; p.c < e ;) {
		switch(state) {
			case header_next:
				//cwarn("next >%-.10s...",p.c);
				c = *p.c;
				if ( unlikely( ( c == TAB || c == ' ' ) ) ) {
					//cwarn("got continuation");
					state = header_cl_sp;
					if ( s->header_i == s->header_max ) {
						cwarn("No more headers could be saved");
						state = skip_line;
						break;
					} else {
						 s->header_i++;
					}
					break;
				}
				else
				if ( unlikely( c == CR ) ) {
					debug("set state = header_last (%02x)", c);
					state = header_last_cr;
					break;
				}
				else
				if ( unlikely( c == LF ) ) {
					//debug("last header line: %02x", c);
					goto last;
				}
				else {
					if ( s->header_i == s->header_max ) {
						cwarn("No more headers could be saved");
						state = skip_line;
						break;
					}
					else {
						state = header_name;
						s->header_i++;
					}
					s->headers[ s->header_i - 1 ].name.str = p.c;
					if( lowcase[c] ) {
						//*p = lowcase[c];
						break;
					}
					else
					if (c == 0) {
						myerror("Invalid header, \\0 encountered");
					}
					else {
						state = skip_line;
						break;
					}
				}
			case header_name:
				//cwarn("parse name from >%-.10s...",p.c);
				p.c = ptr = strchrnul(p.c, ':');
				if ( unlikely( *p.c == 0 ) ) goto shortread;
				if ( unlikely( *p.c == ' ' || *p.c == TAB ) ) {
					for(; *ptr == ' ' || *ptr == TAB; ptr--);
				}
				s->headers[ s->header_i - 1 ].name.len = ptr - s->headers[ s->header_i - 1 ].name.str;
				p.c++;
				//cwarn("parsed name till >%-.10s...",p.c);
				state = header_cl_sp;
				break;
			case header_cl_sp:
				if ( *p.c == ' ' || *p.c == TAB ) {
					p.c++;
					break;
				}
				if ( unlikely( *p.c == 0 ) ) goto shortread;
				s->headers[ s->header_i - 1 ].val.str = p.c;
				state = header_val;
				//cwarn("parsed sp till >%-.10s...",p.c);
				//no break;
			case header_val:
				//cwarn("parse val from >%-.10s...",p.c);
				p.c = ptr = strchrnul(p.c, LF);
				if ( unlikely( *p.c == 0 ) ) goto shortread;
				
				if (*(ptr-1) == CR) ptr--;
				s->headers[ s->header_i - 1 ].val.len = ptr - s->headers[ s->header_i - 1 ].val.str;
				p.c++;
				state = header_next;
				break;
			case skip_line:
				//cwarn("skip line >%-.10s...",p.c);
				p.c = ptr = strchrnul(p.c, LF);
				if ( unlikely( *p.c == 0 ) ) goto shortread;
				p.c++;
				state = header_next;
				break;
			case header_last_cr:
				if ( *p.c == '\r' ) {
					p.c++;
					//c = *++p;
				}
				state = header_last_lf;
				if ( unlikely( p.c == e ) ) goto shortread;
			case header_last_lf:
				if ( *p.c == '\n' ) {
					p.c++;
					goto last;
				} else {
					snprintf(err,256,"Expected LF, received %02x", *p.c);
					goto error;
				}
			default:
				myerror("Unhandled state: %d",state);
		}
	}
	shortread:
		debug("not enough data");
		s->p = p.c;
		s->state = state;
		return -1;
	
	last: {
		debug("done. Body start: >%-.10s'", p);
		char *begin = s->p;
		s->p = p.c;
		//(void) hv_stores( r->headers, "Length", newSViv( p - r->rbuf ));
		
		return p.c - begin;
	}
	error:
		cwarn("parse error: %s", err);
		//call_error(r, newSVpvf("HTTP headers parse error: %s",err));
		return -1024;

	
	return -1;
}

int parse_http_request(parse_http_state * s) {
	register parser_state  state = s->state;  // state of parsing
	register char *p             = s->p;      // main pointer
	register char *e             = s->e;      // end of buffer
	register unsigned char c;                 // current char
	
	char *msg;
	(void)msg;
	int i;
	
	char err[256];err[0] = 0;
#define myerror(msg, ...) do {\
	snprintf(err,256,msg " at %s line %d\n", ##__VA_ARGS__, __FILE__, __LINE__); \
	fprintf(stderr, msg " at %s line %d\n", ##__VA_ARGS__, __FILE__, __LINE__); \
	goto error; \
} while(0)
	
	//          4   8
	// need: HTTP/x.x XXX ?
	if (unlikely( e - p < 14 )) goto shortread;
	if (strncmp(p, "HTTP/", 5) != 0) myerror("HTTP/ expected");
	p+=5;
	if ( likely( *p == '1' && *(p+1) == '.' ) ) {
		
	}
	/*
	for (; p < e; p++) {
		if ( (c >= '0' && c <= '9' ) ) {
			i = i * 10 + c - '0';
		}
		el
	}
	*/
	
	return 0;
	
	for (; p < e; p++) {
		c = *p;
		switch(state) {
			case start:
				if (unlikely( e - p < 5 )) goto shortread;
				if (strncmp(p, "HTTP/", 5) == 0) {
					p += 4;
					i = 0;
					msg = p+1;
					state = version;
					break;
				} else {
					snprintf(err,256,"Expected 'HTTP/', received '%-.5s'...", p);
					goto error;
				}
				//break;
			case version:
				if ( (c >= '0' && c <= '9' ) ) {
					i = i * 10 + c - '0';
					break;
				}
				else
				if ( c == '.' ) {
					s->version.major = i;
					i = 0;
					state = version_minor;
					break;
				}
				else {
					myerror("Bad version: ..%-.5s...", p);
				}
				break;
			case version_minor:
				//warn("read ver min from >%-.10s...", p);
				if ( (c >= '0' && c <= '9' ) ) {
					i = i * 10 + c - '0';
					break;
				}
				else
				if (c != ' ' && c != TAB) {
					// skip?
					break;
				}
				s->version.minor = i;
				state = status_sp;
				//break;
			case status_sp:
				if (c == ' ' || c == TAB) {
					break;
				}
				i = 0;
				state = status;
				//break;
			case status:
				if ( (c >= '0' && c <= '9' )) {
					i = i * 10 + c - '0';
					break;
				}
				s->status = i;
				state = message_sp;
				//break;
			case message_sp:
				if (c == ' ' || c == TAB) {
					break;
				}
				s->reason.str = p;
				state = message;
				//break;
			case message:
				if ( unlikely(c != CR && c != LF ) ) {
					break;
				}
				s->reason.len = p - s->reason.str;
				state = cr;
				//break;
			case cr:
				if ( c == CR ) {
					c = *++p;
				}
				state = lf;
				if ( p == e ) {
					debug("short read just after 1st line");
					goto shortread;
				}
				//break;
			case lf:
				if ( c == LF ) {
					state = header_next;
					break;
				} else {
					myerror("Expected LF, received %02x", c);
				}
				break;
			case header_next:
				//debug("header next: %02x", c);
				if ( unlikely( ( c == TAB || c == ' ' ) ) ) {
					state = header_cl_sp;
					if ( s->header_i == s->header_max ) {
						cwarn("No more headers could be saved");
						state = skip_line;
						break;
					} else {
						 s->header_i++;
					}
					break;
				}
				else
				if ( unlikely( c == CR ) ) {
					debug("set state = header_last (%02x)", c);
					state = header_last_cr;
					break;
				}
				else
				if ( unlikely( c == LF ) ) {
					//debug("last header line: %02x", c);
					goto last;
				}
				else {
					if ( s->header_i == s->header_max ) {
						cwarn("No more headers could be saved");
						state = skip_line;
						break;
					}
					else {
						state = header_name;
						s->header_i++;
					}
					s->headers[ s->header_i - 1 ].name.str = p;
					if( lowcase[c] ) {
						//*p = lowcase[c];
						break;
					}
					else
					if (c == 0) {
						myerror("Invalid header, \\0 encountered");
					}
					else {
						state = skip_line;
						break;
					}
				}
			case header_name:
				//if (!hdr) hdr = p;
				if (lowcase[c]) {
					//*p = lowcase[c];
					//r->lch[i++] = lc;
					//i &= (LC_HEADER_LEN - 1);
					break;
				}
				
				
				//r->lch[  i & (LC_HEADER_LEN - 1) ] = 0;
				s->headers[ s->header_i - 1 ].name.len = p - s->headers[ s->header_i - 1 ].name.str;
				
				/*
				if (strncmp( hdr, "content-length", hdrl ) == 0) {
					r->parse.header = hd_clength;
					i = 0;
				}
				else
				if (strncmp( hdr, "connection", hdrl ) == 0) {
					r->parse.header = hd_connection;
					i = 0;
				}
				else
				if (strncmp( hdr, "transfer-encoding", hdrl ) == 0) {
					r->parse.header = hd_tr_encoding;
					i = 0;
				}
				else
				{
					//warn("compare %s failed", r->lch);
					r->parse.header = hd_other;
				}
				*/
				
				switch(c) {
					case ':':
						state = header_cl_sp;
						break;
					case ' ':
					case TAB:
						state = header_sp;
						break;
					case CR:
						//(void) hv_store( r->headers, hdr, hdrl, &PL_sv_undef, 0 );
						//hdrvl = 0; // value is 0
						state = skip_line;
						break;
					case LF:
						state = header_next;
						break;
					
				}
				break;
				//if (c != ' ' && c != TAB && c != ':') {
				//	break;
				//}
				
			case header_sp:
				if (c == ' ' || c == TAB) {
					break;
				}
				state = header_cl;
			case header_cl:
				if(c == ':') {
					state = header_cl_sp;
					break;
				} else {
					myerror("Expected ':', received '%c' (%02x)", c, c);
					goto error;
				}
				state = header_cl;
			case header_cl_sp:
				if(c == ' ' || c == TAB) {
					break;
				}
				state = header_val;
				s->headers[ s->header_i - 1 ].val.str = p;
			case header_val:
				if (c != CR && c != LF ) {
					break;
				}
				/*
				switch(r->parse.header) {
					case hd_clength:
						i = 0;
						;
						for ( msg = hdrv ; msg < p; msg++ ) {
							if ( (*msg >= '0' && *msg <= '9' )) {
								i = i * 10 + *msg - '0';
							}
							else
							if ( *msg == ' ' || *msg == TAB ) {
								//skip if
							}
							else {
								myerror("Expected digits in content-length field, received: %02x",*msg);
							}
						}
						r->h.content_length = i;
						//warn("Content-Length = %d", i);
						break;
					case hd_tr_encoding:
						if (strncasecmp( hdrv, "chunked", p - hdrv ) == 0) {
							r->h.chunked = 1;
							//warn("Transfer-Encoding=chunked");
						}
						else {
							debug("Unknown transfer-encoding: %-.*s", (int)( p - hdrv ), hdrv );
						}
						break;
					case hd_connection:
						
						if (strncasecmp( hdrv, "keep-alive", p - hdrv ) == 0) {
							r->h.connection = connection_keepalive;
							//warn("Connection = KA");
						}
						else
						if (strncasecmp( hdrv, "close", p - hdrv ) == 0) {
							r->h.connection = connection_close;
						}
						else {
							r->h.connection = connection_close;
							debug("Unknown connection: %-.*s", (int)(p - hdrv), hdrv );
						}
					default:
						break;
				}
				*/
				
				s->headers[ s->header_i - 1 ].val.len = p - s->headers[ s->header_i - 1 ].val.str;
				
				state = header_cr;
			case header_cr:
				if ( c == '\r' ) {
					c = *++p;
				}
				state = lf;
				if ( p == e ) {
					debug("short read on header_cl");
					goto shortread;
				}
				//break;
			case header_lf:
				if ( c == '\n' ) {
					state = header_next;
					break;
				} else {
					myerror("Expected LF, received %02x", c);
				}
			case header_last_cr:
				if ( c == '\r' ) {
					c = *++p;
				}
				state = header_last_lf;
				if ( p == e ) goto shortread;
			case header_last_lf:
				if ( c == '\n' ) {
					p++;
					goto last;
				} else {
					snprintf(err,256,"Expected LF, received %02x", c);
					goto error;
				}
			case skip_line:
				switch(c) {
					case LF:
						state = header_next;
						break;
					default:
						break;
				}
				break;
			default:
				myerror("Unhandled state: %d", state);
		}
	}
	
	//debug("short read by unloop");
	shortread:
		debug("not enough data");
		s->p = p;
		s->state = state;
		return -1;
	
	last: {
		debug("done. Body start: >%-.10s", p);
		char *begin = s->p;
		s->p = p;
		//(void) hv_stores( r->headers, "Length", newSViv( p - r->rbuf ));
		
		return p - begin;
	}
	error:
		debug("parse error: %s", err);
		//call_error(r, newSVpvf("HTTP headers parse error: %s",err));
		return -1024;
}
