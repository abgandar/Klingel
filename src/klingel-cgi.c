/*
 * Copyright (C) 2016-2017 Alexander Wittig <alexander@wittig.name>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA 
 */

/**
 * klingel-cgi.c
 *
 * CGI program to connect to the klingel daemon and send an open door code
 * passed as the query string, or to ring the bell on an empty query.
 *
 * Simply make the klingel.cgi binary executable by your web server. 
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

#include "config.h"

// convert single hex digit to binary number
char hex_to_char( const char c )
{
    switch( c )
    {
        case '0':
        case '1':
        case '2':
        case '3':
        case '4':
        case '5':
        case '6':
        case '7':
        case '8':
        case '9':
            return c-'0';

        case 'A':
        case 'B':
        case 'C':
        case 'D':
        case 'E':
        case 'F':
            return c-'A'+10;

        case 'a':
        case 'b':
        case 'c':
        case 'd':
        case 'e':
        case 'f':
            return c-'a'+10;
    }

    return -1;
}

// URL decode entire string (result must later be free-ed by caller).
// Invalid %XX escape sequences are ignored and produce no output.
char* urldecode( const char *str )
{
    char *dup = strdup( str ), *p = dup, *q = dup;

    // literal copy up to next % or end of string
    for( ; *p != '\0' && *p != '%'; p++, q++ ) *q = *p;
    while( *p != '\0' )
    {
        // we're at a % sign, URL decode this sequence
        p++;
        const char c1 = hex_to_char( *p );
        if( *p != '\0' ) p++;
        const char c2 = hex_to_char( *p );
        if( *p != '\0' ) p++;
        if( c1 != -1 && c2 != -1 )
        {
            *q = c1<<4 | c2;
            q++;
        }

        // literal copy up to next % or end of string
        for( ; *p != '\0' && *p != '%'; p++, q++ ) *q = *p;
    }
    *q = '\0';

    return dup;
}

// Main program entry point
int main( int argc, char *argv[] )
{
    // get query string from CGI environment
    const char *arg = getenv( "QUERY_STRING" );
    if( arg == NULL )
    {
        puts( "Status: 400 Bad Request" );
        puts( "Content-type: application/json\n" );
        puts( "{\"status\":400,\"message\":\"Request incomplete\"}" );
        return 400;
    }

    // open FIFO pipe to main klingel daemon
    int fd = open( FIFO_PFAD, O_WRONLY );
    if( fd == -1 )
    {
        puts( "Status: 500 Internal Server Error" );
        puts( "Content-type: application/json\n" );
        puts( "{\"status\":500,\"message\":\"Request failed\"}" );
        return 500;
    }

    // URL decode argument
    char *argdec = urldecode( arg );
    if( argdec == NULL )
    {
        puts( "Status: 500 Internal Server Error" );
        puts( "Content-type: application/json\n" );
        puts( "{\"status\":500,\"message\":\"Request failed\"}" );
        close( fd );
        return 500;
    }

    // decode and send argument
    write( fd, argdec, strlen( argdec ) );
    free( argdec );
    close( fd );

    puts( "Content-type: application/json\n" );
    puts( "{\"status\":200,\"message\":\"Request accepted\"}" );

    return 0;
}
