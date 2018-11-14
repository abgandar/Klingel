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
 * klingel.c
 *
 * This simple door bell module for use with BeagleBone or Raspberry Pi like
 * devices.
 * It has the following capabilities:
 *  - Register with a SIP registrar service
 *  - Ring external bell and make SIP call when door bell is pushed
 *  - Receive SIP call to allow listening to door device
 *  - Activate door opener from SIP call via predefined DTMF sequence or via
 *    external local fifo socket
 *
 * Usage:
 *  - Connect the door speaker and microphone to the default sound device on
 *    your platform.
 *  - Connect the door bell call button to a GPIO pin via a pull-down resistor
 *  - Connect the door opener and external bell via a relay to GPIO pins
 *  - Run the klingel.service via systemctl 
 *
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <grp.h>
#include <ctype.h>
#include <signal.h>
#include <fcntl.h>
#include <poll.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdarg.h>
#include <unistd.h>
#include <crypt.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <pjsua-lib/pjsua.h>

#include "config.h"

#define STR_LEN         255                     // Maximale Länge für strings in GPIO code
#define SYSFS_NUM       10                      // Zahl der Versuche die erste SYSFS Datei nach Export zu öffnen
#define SYSFS_DAUER     50                      // Zeitdauer in Millisekunden zwischen SYSFS Versuchen
#define SIP_DAUER       1000                    // Zeitdauer in Millisekunden um auf SIP Initialisierung zu warten

// Door opener thread synchronization
static pthread_mutex_t dtmf_mutex   = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t opener_cond   = PTHREAD_COND_INITIALIZER;
static char dtmf[DTMF_MAX+1]        = { 0 };
static unsigned int ndtmf           = 0;

// Thread ids and global flag indicating the program is running
static pthread_t door_opener = { 0 }, pipe_reader = { 0 }, bell_button = { 0 };
static bool running = PJ_TRUE;
static bool klingel = PJ_FALSE;

// GPIO constants and files
static int tfd = -1, gfd = -1, kfd = -1;       // File descriptor of Türe, Glocke and Klingeltaster
static int fdexport = -1, fdunexport = -1;
enum io_dir { IN, OUT, HIGH, LOW };
static const char* dirs[] = { "in", "out", "high", "low" };
enum io_edge { NONE, RISING, FALLING, BOTH };
static const char* edges[] = { "none", "rising", "falling", "both" };

// PJSUA account and call timer
static pjsua_acc_id acc_id = -1;
static struct pj_timer_entry timer = { 0 };

/**** Utility functions ****/

// forward declaration
static void destroy( );

// Display pjsua error message and exit application
static void error_exit_pj( const char *title, const pj_status_t status )
{
    pjsua_perror( __FILE__, title, status );
    destroy( );
    exit( 1 );
}

// Display pjsua error message and exit application
static void error_exit( const char *title, ... )
{
    va_list list;
    va_start( list, title );
    vfprintf( stderr, title, list );
    va_end( list );
    putc( '\n', stderr );
    destroy( );
    exit( 1 );
}

// open the GPIO export / unexport files
static void initGPIO(  )
{
    if( fdexport == -1 )
    {
        fdexport = open( "/sys/class/gpio/export", O_WRONLY | O_NONBLOCK );
        if( fdexport == -1 )
            error_exit( "Failed to open 'export' for opening pins!" );
    }

    if( fdunexport == -1 )
    {
        fdunexport = open( "/sys/class/gpio/unexport", O_WRONLY | O_NONBLOCK );
        if( fdunexport == -1 )
            fprintf( stderr, "Failed to open 'unexport' for closing pins!\n" );   // not catastrophic
    }
}

// close GPIO related export / unexport files
static void destroyGPIO(  )
{
    if( fdexport != -1 )
    {
        close( fdexport );
        fdexport = -1;
    }

    if( fdunexport != -1 )
    {
        close( fdunexport );
        fdexport = -1;
    }
}

// open the given GPIO pin with specified settings
static int openPin( const int pin, const enum io_dir direction, const enum io_edge edge )
{
    char str[STR_LEN];

    // export the pin
    if( fdexport == -1 )
        error_exit( "Pin export not initialized while opening pin %d!", pin );
    int len = snprintf( str, STR_LEN, "%d", pin );
    write( fdexport, str, len );
    fsync( fdexport );

    // set direction of GPIO pin
    snprintf( str, STR_LEN, "/sys/class/gpio/gpio%d/direction", pin );
    int fd = open( str, O_WRONLY | O_NONBLOCK );
    int i;
    for( i = 0; i < SYSFS_NUM && fd == -1; i++ )
    {
        // give the system time to create nodes and adjust file permissions (does not seem to be atomic!)
        pj_thread_sleep( SYSFS_DAUER );
        fd = open( str, O_WRONLY | O_NONBLOCK );
    }
    if( fd == -1 )
        error_exit( "Failed to open 'direction' for setting pin %d after %d tries!", pin, SYSFS_NUM );
    write( fd, dirs[direction], strlen( dirs[direction] ) );
    close( fd );

    // set edge of GPIO pin
    snprintf( str, STR_LEN, "/sys/class/gpio/gpio%d/edge", pin );
    fd = open( str, O_WRONLY | O_NONBLOCK );
    if( fd == -1 )
        error_exit( "Failed to open 'edge' for setting pin %d!", pin );
    write( fd, edges[edge], strlen( edges[edge] ) );
    close( fd );

    // finally open GPIO pin for reading
    snprintf( str, STR_LEN, "/sys/class/gpio/gpio%d/value", pin );
    fd = open( str, O_NONBLOCK | (direction == IN ? O_RDONLY : O_WRONLY) );
    if( fd == -1 )
        error_exit( "Failed to exclusively open 'value' for reading/writing pin %d!", pin );
    flock( fd, LOCK_EX );       // try to get an exclusive lock to prevent other processes from interfering

    return fd;
}

// close the given GPIO pin and file
static void closePin( const int pin, const int fd )
{
    char str[STR_LEN];

    if( fd != -1 )
        close( fd );

    // unexport the pin
    if( fdunexport == -1 )
    {
        fprintf( stderr, "Pin unexport not initialized while closing pin %d!\n", pin );
        return;     // don't treat as catastrophic
    }
    const int len = snprintf( str, STR_LEN, "%d", pin );
    write( fdunexport, str, len );
}

// handle signals to allow coordinated exit of program (used both in main program and threads)
void sighandler( int sig )
{
    switch( sig )
    {
        case SIGINT:
            // Quit the program in an orderly fashion
            running = PJ_FALSE;
            // Wake up door opener thread so it can finish (but without opening). It doesn't work with signals.
            pthread_mutex_lock( &dtmf_mutex );
            dtmf[0] = '\0';
            pthread_cond_signal( &opener_cond );
            pthread_mutex_unlock( &dtmf_mutex );
            // send signal to other threads so they wakes up from poll/read
            pthread_kill( pipe_reader, SIGHUP );
            pthread_kill( bell_button, SIGHUP );
            break;
    }
}

/**** Worker threads ****/

// Wait for signal to open door and activate door opener switch via pipe
void* pipe_thread( void *param )
{
    char str[5+DTMF_MAX+1] = { 0 };

    // register this thread with PJSUA library as it calls PJSUA functions
    pj_thread_desc desc = { 0 };
    pj_thread_t *this_thread = NULL;
    pj_thread_register( __func__, desc, &this_thread );

     // handle signal to terminate (SIGHUP), it's enough that we wake up from it so handler is a noop
    struct sigaction sig = { 0 };
    sig.sa_handler = &sighandler;
    sigaction( SIGHUP, &sig, NULL );

    while( running )
    {
        // open new pipe (sleeps till ready)
        int pfd = open( FIFO_PFAD, O_RDONLY );
        if( pfd == -1 )
        {
            if( errno == EINTR )
                continue;
            else
                error_exit( "Error opening fifo pipe at %s", FIFO_PFAD );
        }

        // read from pipe and close
        const int len = read( pfd, str, 5+DTMF_MAX );
        close( pfd );
        if( len <= 0 ) continue;
        str[len] = '\0';
        PJ_LOG( 4, ( __func__, "pipe input received" ) );

        // Interpret input
        if( strcmp( str, "ring" ) == 0 )
        {
            // Just ring the bell
            klingel = PJ_TRUE;
            pthread_kill( bell_button, SIGHUP );
            PJ_LOG( 4, ( __func__, "pipe ringing bell" ) );
        }
        else if( strncmp( str, "open:", 5 ) == 0 )
        {
            // Copy code to DTMF sequence and activate door open thread
            pthread_mutex_lock( &dtmf_mutex );
            strncpy( dtmf, str+5, DTMF_MAX+1 );
            dtmf[DTMF_MAX] = '\0';      // just for good measure
            pthread_cond_signal( &opener_cond );
            pthread_mutex_unlock( &dtmf_mutex );
            PJ_LOG( 4, ( __func__, "pipe opening door" ) );
        }
        memset( str, 0, 5+DTMF_MAX+1 );
    }

    PJ_LOG( 4, ( __func__, "pipe thread done" ) );
    return NULL;
}

// Wait for signal to open door and activate door opener switch
void* opener_thread( void *param )
{
    pj_time_val last = { 0 };
    unsigned int count = 0;

    // register this thread with PJSUA library as it calls PJSUA functions
    pj_thread_desc desc = { 0 };
    pj_thread_t *this_thread = NULL;
    pj_thread_register( __func__, desc, &this_thread );

    // handle signal to terminate (SIGHUP), it's enough that we wake up from it so handler is a noop
    struct sigaction sig = { 0 };
    sig.sa_handler = &sighandler;
    sigaction( SIGHUP, &sig, NULL );

    pj_gettimeofday( &last );
    while( running )
    {
        pthread_mutex_lock( &dtmf_mutex );
        pthread_cond_wait( &opener_cond, &dtmf_mutex );
        dtmf[DTMF_MAX] = '\0';  // zero terminate just to be sure
        const bool correct = (strcmp( TUERCODE, crypt( dtmf, TUERCODE ) ) == 0);
        memset( dtmf, 0, DTMF_MAX+1 );
        ndtmf = 0;
        pthread_mutex_unlock( &dtmf_mutex );

        // 1) check if program is still running
        if( !running )
            break;

        // 2) check rate limit
        pj_time_val now;
        pj_gettimeofday( &now );
        const int diff = (now.sec - last.sec)*1000 + (now.msec - last.msec);
        if( diff < RATE_LIMIT )
        {
            if( count > RATE_MAX )
            {
                // show rate limit warning only once
                if( count == RATE_MAX+1 )
                {
                    PJ_LOG( 4, ( __func__, "rate limit hit" ) );
                    count++;
                }
                continue;    // ignore any input after limit is hit
            }
        }
        else
        {
            last = now;
            count = 0;
        }

        // 3) check code
        if( !correct )
        {
            PJ_LOG( 4, ( __func__, "wrong code" ) );
            count++;
            continue;
        }

        // send open door command then deactivate again
        PJ_LOG( 3, ( __func__, "Türöffner aktiviert" ) );
        write( tfd, "1\n", 2 );
        fsync( tfd );    // may not be needed, but we call it anyway
        pj_thread_sleep( TUER_DAUER );
        unsigned int i;
        for( i = 1; i < TUER_LOOPS; i++ )
        {
            write( tfd, "0\n", 2 );
            fsync( tfd );
            pj_thread_sleep( TUER_DAUER );
            write( tfd, "1\n", 2 );
            fsync( tfd );    // may not be needed, but we call it anyway
            pj_thread_sleep( TUER_DAUER );
        }
        // set back to zero
        write( tfd, "0\n", 2 );
        fsync( tfd );
    }

    // set opener back to zero (just to be sure in case we were interrupted somehow)
    write( tfd, "0\n", 2 );
    fsync( tfd );
    PJ_LOG( 4, ( __func__, "opener thread done" ) );
    return NULL;
}

// Wait for door bell to be pushed
void* klingel_thread( void *param )
{
    // register this thread with PJSUA library as it calls PJSUA functions
    pj_thread_desc desc = { 0 };
    pj_thread_t *this_thread = NULL;
    pj_thread_register( __func__, desc, &this_thread );

    // handle signal to terminate (SIGHUP), it's enough that we wake up from it
    struct sigaction sig = { 0 };
    sig.sa_handler = &sighandler;
    sigaction( SIGHUP, &sig, NULL );

    // SIP URIs
    const pj_str_t uri_tag   = pj_str( SIP_TAG_URI ),
                   uri_nacht = pj_str( SIP_NACHT_URI );

    // Wait for the bell button to be pushed
    struct pollfd fds;
    fds.fd = kfd;
    fds.events = POLLPRI | POLLERR;
    while( running )
    {
        // poll until the bell button is pushed (or a signal is received, such as SIGHUP)
        poll( &fds, 1, -1 );

        // check if button has really been pushed or if we were triggered externally.
        if( klingel )
        {
            klingel = PJ_FALSE;
        }
        else
        {
            // To avoid spurious bouncing and flipping with bad switches, we check with a bit of delay
            pj_thread_sleep( KLINGEL_DAUER );
            char str = '\0';
            lseek( kfd, 0, SEEK_SET );
            read( kfd, &str, 1 );
            PJ_LOG( 4, ( __func__, "door bell value: %c", str ) );
            if( str != '1' ) continue;  // if it's not 1 we ignore this event
        }
        PJ_LOG( 3, ( __func__, "Klingel aktiviert" ) );

        // determine time of day
        pj_time_val loctime;
        pj_gettimeofday( &loctime );
        pj_parsed_time pt;
        pj_time_decode( &loctime, &pt );
        const int t = pt.hour*100 + pt.min;
#if NACHTRUHE_START < NACHTRUHE_ENDE
        const bool nacht = (t >= NACHTRUHE_START) && (t <= NACHTRUHE_ENDE);
#else
        const bool nacht = (t >= NACHTRUHE_START) || (t <= NACHTRUHE_ENDE);     // korrekte Behandlung von Mitternacht
#endif
        const pj_str_t *uri = nacht ? &uri_nacht : &uri_tag;

        // make the call - if the URL is valid and there's no other active call already
        if( (pj_strlen( uri ) > 0) && (pjsua_call_get_count( ) == 0) )
        {
            PJ_LOG( 4, ( __func__, "calling" ) );
            pjsua_call_id call_id;
            pj_status_t status = pjsua_call_make_call( acc_id, uri, NULL, NULL, NULL, &call_id );
            if( status != PJ_SUCCESS )
            {
                // don't quit on errors, just print a message
                pjsua_perror( __func__, "Error making call", status );
            }
        }

        // ding dong - if it's not the middle of the night
        if( !nacht )
        {
            PJ_LOG( 4, ( __func__, "ding dong" ) );
            write( gfd, "1\n", 2 );
            fsync( gfd );    // may not be needed, but we call it anyway
            pj_thread_sleep( GLOCKE_DAUER );
            unsigned int i;
            for( i = 1; i < GLOCKE_LOOPS; i++ )
            {
                write( gfd, "0\n", 2 );
                fsync( gfd );
                pj_thread_sleep( GLOCKE_DAUER );
                write( gfd, "1\n", 2 );
                fsync( gfd );
                pj_thread_sleep( GLOCKE_DAUER );
            }
            write( gfd, "0\n", 2 );
            fsync( gfd );
        }
    }

    PJ_LOG( 4, ( __func__, "klingel thread done") );

    return NULL;
}

/**** Callbacks for PJSUA library ****/

// Callback timer to disconnect call (limiting call duration)
static void timer_disconnect_call( pj_timer_heap_t *timer_heap, struct pj_timer_entry *entry )
{
    pjsua_call_id call_id = entry->id;
    if( pjsua_call_is_active( call_id ) )
        pjsua_call_hangup( call_id, 0, NULL, NULL );    // 0 defaults to 603 = Decline
    entry->id = 0;

    PJ_LOG( 4, ( __func__, "call/ring duration exceeded" ) );
}

// Callback for receiving an incoming call
static void on_incoming_call( pjsua_acc_id acc_id, pjsua_call_id c_id, pjsip_rx_data *rdata )
{
    // if there's another active call already we reject the new call
    if( pjsua_call_get_count( ) > 1 )
    {
        pjsua_call_answer( c_id, 486, NULL, NULL );     // 486 = Busy
        PJ_LOG( 4, ( __func__, "call rejected" ) );
    }
    else
    {
        pjsua_call_answer( c_id, 200, NULL, NULL );     // 200 = OK
        PJ_LOG( 4, ( __func__, "call accepted" ) );
    }
}

// Callback for changes in call state
static void on_call_state( pjsua_call_id c_id, pjsip_event *e )
{
    pjsua_call_info ci;

    pjsua_call_get_info( c_id, &ci );
    if( ci.state == PJSIP_INV_STATE_CALLING )
    {
        // cancel any possibly existing previous timer just to be sure
        pjsua_cancel_timer( &timer );

#if MAX_RING_TIME>0
        // schedule a timer for disconnecting the call after max. ring time
        timer.id = c_id;
        timer.cb = &timer_disconnect_call;
        pj_time_val t = { 0 };
        t.msec = MAX_RING_TIME;
	    pjsua_schedule_timer( &timer, &t );
#endif
    }
    else if( ci.state == PJSIP_INV_STATE_CONFIRMED )
    {
        // cancel any possibly existing previous timer (e.g. from ringing) just to be sure
        pjsua_cancel_timer( &timer );

#if MAX_CALL_TIME>0
        // schedule a timer for disconnecting the call after max. time
        timer.id = c_id;
        timer.cb = &timer_disconnect_call;
        pj_time_val t = { 0 };
        t.msec = MAX_CALL_TIME;
	    pjsua_schedule_timer( &timer, &t );
#endif
    }
    else if( ci.state == PJSIP_INV_STATE_DISCONNECTED )
    {
        // cancel any possibly remaining timers
        pjsua_cancel_timer( &timer );
    }
}

// Callback called by the library when call's media state has changed
static void on_call_media_state( pjsua_call_id c_id )
{
    pjsua_call_info ci;

    pjsua_call_get_info( c_id, &ci );
    if( ci.media_status == PJSUA_CALL_MEDIA_ACTIVE )
    {
        // When media is active, connect call to sound device.
        pjsua_conf_connect( 0, ci.conf_slot );  // door -> phone
        pjsua_conf_connect( ci.conf_slot, 0 );  // phone -> door

        // adjust input/output volumes
        pjsua_conf_adjust_tx_level( 0, VOL_SPEAKER );
        pjsua_conf_adjust_rx_level( 0, VOL_MIC );
        //pjsua_conf_adjust_tx_level( ci.conf_slot, 1.0 );    // just for good measure?
        //pjsua_conf_adjust_rx_level( ci.conf_slot, 1.0 );
    }
}

// DTMF digit received
static void on_dtmf_digit( pjsua_call_id c_id, int digit )
{
    if( digit == '#' || digit == '*' )
    {
        PJ_LOG( 4, ( __func__, "DTMF send door code" ) );

        // Send opener code (also automatically resets the code) and reconnect audio
        pthread_mutex_lock( &dtmf_mutex );
        pthread_cond_signal( &opener_cond );
        pthread_mutex_unlock( &dtmf_mutex );

        pjsua_conf_connect( 0, pjsua_call_get_conf_port( c_id ) );   // door -> phone
        pjsua_conf_connect( pjsua_call_get_conf_port( c_id ), 0 );   // phone -> door
    }
    else
    {
        // on first DTMF signal disconnect audio so following DTMF sequences can't be injected from door
        if( ndtmf == 0 )
        {
            pjsua_conf_disconnect( 0, pjsua_call_get_conf_port( c_id ) );   // door -> phone
            pjsua_conf_disconnect( pjsua_call_get_conf_port( c_id ), 0 );   // phone -> door
        }

        if( ndtmf < DTMF_MAX )
        {
            // Add character to DTMF sequence
            pthread_mutex_lock( &dtmf_mutex );
            dtmf[ndtmf] = digit;
            ndtmf++;
            dtmf[ndtmf] = '\0';
            pthread_mutex_unlock( &dtmf_mutex );

            PJ_LOG( 4, ( __func__, "DTMF character received" ) );
        }
    }
}

/**** Main program ****/

// initialize GPIO and drop privileges if configured
static void init_privileged( )
{
    // open GPIO pins
    initGPIO( );
	tfd = openPin( TUER_PIN, LOW, NONE );
	kfd = openPin( KLINGEL_PIN, IN, RISING );
    gfd = openPin( GLOCKE_PIN, LOW, NONE );

    close( fdexport );      // close export file explicitly to prevent further pins from opening
    fdexport = -1;

    // set up fifo
    unlink( FIFO_PFAD );    // we're egoistic: this is our fifo (can't remove at end because we drop privileges). If we were able to open the pins we're probably the only instance...
    mode_t oldmode = umask( 0 );
    if( mkfifo( FIFO_PFAD, S_IRUSR | S_IWUSR | S_IWGRP | S_IWOTH ) == -1 )
        error_exit( "mkfifo: Error creating fifo pipe at %s", FIFO_PFAD );
    umask( oldmode );

#ifdef UNPRIV_USER
    // drop privileges if needed now that init is done
    if( getuid( ) == 0 )
    {
        const struct passwd *pwd = getpwnam( UNPRIV_USER );
        if( pwd == NULL )
            error_exit( "getpwnam: Unable to get unprivileged user data for %s", UNPRIV_USER );

        chown( FIFO_PFAD, pwd->pw_uid, pwd->pw_gid );

        if( initgroups( UNPRIV_USER, pwd->pw_gid ) != 0 )
            error_exit( "setgid: Unable to drop group privileges" );
        if( setuid( pwd->pw_uid ) != 0 )
            error_exit( "setgid: Unable to drop user privileges" );
    }
#endif
}

// initialize pjsua library and register SIP
static void init( )
{
    // handle external signals to terminate and open door (Ctrl+c = SIGINT)
    struct sigaction sig = { 0 };
    sig.sa_handler = &sighandler;
    sigaction( SIGINT, &sig, NULL );

    // Create pjsua first
    pj_status_t status = pjsua_create( );
    if( status != PJ_SUCCESS ) error_exit_pj( "Error in pjsua_create( )", status );

    // Init pjsua library
	pjsua_config cfg;
	pjsua_config_default( &cfg );
    cfg.max_calls = 1;
	cfg.cb.on_incoming_call = &on_incoming_call;
	cfg.cb.on_call_state = &on_call_state;
	cfg.cb.on_call_media_state = &on_call_media_state;
    cfg.cb.on_dtmf_digit = &on_dtmf_digit;

	pjsua_logging_config lcfg;
	pjsua_logging_config_default( &lcfg );
#ifdef DEBUG
	lcfg.console_level = 4;
#else
	lcfg.console_level = 3;
#endif

	status = pjsua_init( &cfg, &lcfg, NULL );
	if( status != PJ_SUCCESS ) error_exit_pj( "Error in pjsua_init( )", status );

    // Add transport
	pjsua_transport_config tcfg;
	pjsua_transport_config_default( &tcfg );
	tcfg.port = 5060;

#if defined(PJSIP_HAS_TLS_TRANSPORT) && defined(WITH_TLS)
#if defined(TLS_CERT_FILE) && defined(TLS_PRIVKEY_FILE)
    tcfg.tls_setting.cert_file = pj_str( TLS_CERT_FILE );
    tcfg.tls_setting.privkey_file = pj_str( TLS_PRIVKEY_FILE );
#if defined(TLS_PRIVKEY_PASSWORD)
    tcfg.tls_setting.password = pj_str( TLS_PRIVKEY_PASSWORD );
#endif
#endif
	status = pjsua_transport_create( PJSIP_TRANSPORT_TLS, &tcfg, NULL );
    PJ_LOG( 4, ( __func__, "TLS transport created" ) );
#elif defined(WITH_UDP6)
	status = pjsua_transport_create( PJSIP_TRANSPORT_UDP6, &tcfg, NULL );
    PJ_LOG( 4, ( __func__, "UDP6 transport created" ) );
#else
	status = pjsua_transport_create( PJSIP_TRANSPORT_UDP, &tcfg, NULL );
    PJ_LOG( 4, ( __func__, "UDP transport created" ) );
#endif
	if( status != PJ_SUCCESS ) error_exit_pj( "Error creating transport", status );

    // Initialization is done, start pjsua
    status = pjsua_start( );
    if( status != PJ_SUCCESS ) error_exit_pj( "Error starting pjsua", status );

    // Register with SIP server
	pjsua_acc_config acfg;
	pjsua_acc_config_default( &acfg );
	acfg.id = pj_str( "\"" SIP_NAME "\" <sip:" SIP_USER "@" SIP_DOMAIN ">" );
	acfg.reg_uri = pj_str( "sip:" SIP_DOMAIN );
    acfg.publish_enabled = PJ_TRUE;
    acfg.reg_timeout = 1800;
	acfg.cred_count = 1;
	acfg.cred_info[0].realm = pj_str( SIP_DOMAIN );
	acfg.cred_info[0].scheme = pj_str( "digest" );
	acfg.cred_info[0].username = pj_str( SIP_USER );
	acfg.cred_info[0].data_type = PJSIP_CRED_DATA_PLAIN_PASSWD;
	acfg.cred_info[0].data = pj_str( SIP_PASSWD );

	status = pjsua_acc_add( &acfg, PJ_TRUE, &acc_id );
	if( status != PJ_SUCCESS ) error_exit_pj( "Error adding account", status );
}

// destroy PJSUA and release other resources
static void destroy( )
{
    // close GPIO
    closePin( KLINGEL_PIN, kfd );
    closePin( GLOCKE_PIN, gfd );
    closePin( TUER_PIN, tfd );
    destroyGPIO( );

    // close and remove pipe
    unlink( FIFO_PFAD );

    // close PJSUA
    pjsua_destroy( );
}

// Main program entry point
int main( int argc, char *argv[] )
{
    // Initialize system (privileged)
    init_privileged( );

    // Initialize system (non-privileged)
    init( );

    // Create threads and join them
    pj_thread_sleep( SIP_DAUER );   // wait a moment to allow SIP to register
    pthread_create( &door_opener, NULL, &opener_thread, NULL );
    pthread_create( &pipe_reader, NULL, &pipe_thread, NULL );
    pthread_create( &bell_button, NULL, &klingel_thread, NULL );
    pthread_join( door_opener, NULL );
    pthread_join( pipe_reader, NULL );
    pthread_join( bell_button, NULL );

    // Destroy everything
    destroy( );

    return 0;
}
