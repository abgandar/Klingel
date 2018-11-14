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
 * crypt.c
 *
 * Little tool to generate a crypted door code for use in the main program.
 *
 * Run as "crypt > code.h" to generate the header file with the door code.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <crypt.h>
#include <string.h>
#include <time.h>
#include <ctype.h>

#define CRYPT_TYPE '6'

static const char *salt_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789./";
static const int salt_chars_len = 64;
//static const int salt_chars_len = strlen( salt_chars );

int main( )
{
    char *pass, salt[100] = { '$', CRYPT_TYPE, '$', 0 };

    fprintf( stderr, "Enter a salt (or empty for random): " );
    fgets( salt+3, 100-3, stdin );
    if( salt[3] == '\n' )
    {
        srand( time( NULL ) );
        unsigned int i;
        for( i = 0; i < 16; i++ )
            salt[3+i] = salt_chars[rand( )%salt_chars_len];
        salt[19] = '$';
        salt[20] = '\0';
    }
    else
    {
        salt[strlen( salt )-1] = '$';     // replace trailing new line by $
    }

    pass = getpass( "Enter door opening code (use only 0-9): " );
    char *p;
    for( p = pass; *p != '\0' && isdigit( *p ); p++ );
    if( p == pass || *p != '\0' )
        fprintf( stderr, "WARNING: door code should consist only of numbers and must not be empty!\n" );

    printf( "#define TUERCODE        \"%s\"\n", crypt( pass, salt ) );

    p = NULL;
    memset( pass, 0, strlen( pass ) );

    return 0;
}
