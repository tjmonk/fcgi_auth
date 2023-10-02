/*==============================================================================
MIT License

Copyright (c) 2023 Trevor Monk

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
==============================================================================*/

/*!
 * @defgroup fcgi_auth fcgi_auth
 * @brief Fast CGI Interface for session authentication
 * @{
 */

/*============================================================================*/
/*!
@file fcgi_auth.c

    FCGI Authentication

    The fcgi_auth Application provides a Fast CGI interface to support
    authentication with the session manager.
    It can be interfaced via a web server such as lighttpd.

*/
/*============================================================================*/

/*==============================================================================
        Includes
==============================================================================*/

#include <string.h>
#include <stdbool.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include <signal.h>
#include <sys/stat.h>
#include <ctype.h>
#include <sessionmgr/sessionmgr.h>
#include <fcgi_stdio.h>

/*==============================================================================
        Private definitions
==============================================================================*/

#ifndef EOK
#define EOK 0
#endif

/*! Maximum POST content length */
#define MAX_POST_LENGTH         1024L

/*! FCGIAuth state */
typedef struct _FCGIAuthState
{
    /*! maximum POST data length */
    size_t maxPostLength;

    /*! POST buffer */
    char *postBuffer;

    /*! count of the output variables */
    size_t outputCount;

    /*! verbose flag */
    bool verbose;

    /*! read only flag */
    bool readonly;

} FCGIAuthState;

/*! Handler function */
typedef int (*HandlerFunction)(FCGIAuthState *);

/*! FCGI Handler function */
typedef struct _fcgi_handler
{
    /*! handler name */
    char *handler;

    /*! handler function */
    HandlerFunction fn;
} FCGIHandler;

/*==============================================================================
        Private function declarations
==============================================================================*/

int main(int argc, char **argv);
static int InitState( FCGIAuthState *pState );
static int ProcessOptions( int argC, char *argV[], FCGIAuthState *pState );
static void usage( char *cmdname );
static int ProcessRequests( FCGIAuthState *pState,
                            FCGIHandler *pFCGIHandlers,
                            size_t numHandlers );

static int ProcessGETRequest( FCGIAuthState *pState );
static int ProcessPOSTRequest( FCGIAuthState *pState );
static int GetPOSTData( FCGIAuthState *pState, size_t length );
static int ProcessUnsupportedRequest( FCGIAuthState *pState );
static int ProcessQuery( FCGIAuthState *pState, char *request );

static int ProcessLoginQuery( FCGIAuthState *pState, char *query );
static int ProcessLogoutQuery( FCGIAuthState *pState, char *query );

static int AllocatePOSTBuffer( FCGIAuthState *pState );
static int ClearPOSTBuffer( FCGIAuthState *pState );
static void SetupTerminationHandler( void );
static void TerminationHandler( int signum, siginfo_t *info, void *ptr );

static HandlerFunction GetHandlerFunction( char *method,
                                           FCGIHandler *pFCGIHandlers,
                                           size_t numHandlers );

static int ErrorResponse( int status,  char *description );
static int AuthSessionResponse( char *session );

static char* base64_decode(char* cipher, char *plain, size_t len);
static char *GetCreds( char *buf, size_t len );

/*==============================================================================
        Private file scoped variables
==============================================================================*/

/*! array of HTTP method handlers */
FCGIHandler methodHandlers[] =
{
    { "GET", ProcessGETRequest },
    { "POST", ProcessPOSTRequest },
    { "*", ProcessUnsupportedRequest }
};

/* FCGI Vars State object */
FCGIAuthState state;

/*==============================================================================
        Private function definitions
==============================================================================*/

/*============================================================================*/
/*  main                                                                      */
/*!
    Main entry point for the fcgi_auth application

    The main function starts the fcgi_auth application

    @param[in]
        argc
            number of arguments on the command line
            (including the command itself)

    @param[in]
        argv
            array of pointers to the command line arguments

    @return none

==============================================================================*/
int main(int argc, char **argv)
{
    /* initialize the FCGI Vars state */
    InitState( &state );

    /* set up the termination handler */
    SetupTerminationHandler();

    /* process the command line options */
    ProcessOptions( argc, argv, &state );

    /* allocate memory for the POST data buffer */
    if( AllocatePOSTBuffer( &state ) == EOK )
    {
        /* process FCGI requests */
        ProcessRequests( &state,
                            methodHandlers,
                            sizeof(methodHandlers) / sizeof(FCGIHandler) );
    }
    else
    {
        syslog( LOG_ERR, "Cannot allocate POST buffer" );
    }

    return 0;
}

/*============================================================================*/
/*  InitState                                                                 */
/*!
    Initialize the FCGIAuth state

    The InitState function initializes the FCGIAuth state object

    @param[in]
        pState
            pointer to the FCGIAuthState object to initialize

    @retval EOK the FCGIAuthState object was successfully initialized
    @retval EINVAL invalid arguments

==============================================================================*/
static int InitState( FCGIAuthState *pState )
{
    int result = EINVAL;

    if ( pState != NULL )
    {
        /* clear the state */
        memset( pState, 0, sizeof( FCGIAuthState ) );

        /* set the default POST content length */
        pState->maxPostLength = MAX_POST_LENGTH;

        result = EOK;
    }

    return result;
}

/*============================================================================*/
/*  usage                                                                     */
/*!
    Display the application usage

    The usage function dumps the application usage message
    to stderr.

    @param[in]
       cmdname
            pointer to the invoked command name

    @return none

==============================================================================*/
static void usage( char *cmdname )
{
    if( cmdname != NULL )
    {
        fprintf(stderr,
                "usage: %s [-v] [-h] "
                " [-h] : display this help"
                " [-v] : verbose output"
                " [-l <max POST length>] : maximum POST data length",
                cmdname );
    }
}

/*============================================================================*/
/*  ProcessOptions                                                            */
/*!
    Process the command line options

    The ProcessOptions function processes the command line options and
    populates the FCGIAuthState object

    @param[in]
        argC
            number of arguments
            (including the command itself)

    @param[in]
        argv
            array of pointers to the command line arguments

    @param[in]
        pState
            pointer to the FCGIAuth state object

    @retval EOK options processed successfully
    @retval ENOTSUP unsupported option
    @retval EINVAL invalid arguments

==============================================================================*/
static int ProcessOptions( int argC, char *argV[], FCGIAuthState *pState )
{
    int c;
    int result = EINVAL;
    const char *options = "hvl:";

    if( ( pState != NULL ) &&
        ( argV != NULL ) )
    {
        result = EOK;

        while( ( c = getopt( argC, argV, options ) ) != -1 )
        {
            switch( c )
            {
                case 'v':
                    pState->verbose = true;
                    break;

                case 'l':
                    pState->maxPostLength = strtoul( optarg, NULL, 0 );
                    break;

                case 'h':
                    usage( argV[0] );
                    break;

                default:
                    result = ENOTSUP;
                    break;

            }
        }
    }

    return result;
}

/*============================================================================*/
/*  ProcessRequests                                                           */
/*!
    Process incoming Fast CGI requests

    The ProcessRequests function waits for incoming FCGI requests
    and processes them according to their request method.
    Typically this function will not exit, as doing so will terminate
    the FCGI interface.

    @param[in]
        pState
            pointer to the FCGIAuth state object

    @param[in]
        pFCGIHandlers
            pointer to an array of FCGIHandler objects which link method
            names (eg GET, POST) with their method handling functions.

    @param[in]
        numHandlers
            number of handlers in the array of FCGIHandler objects

    @retval EOK request processed successfully
    @retval EINVAL invalid arguments

==============================================================================*/
static int ProcessRequests( FCGIAuthState *pState,
                            FCGIHandler *pFCGIHandlers,
                            size_t numHandlers )
{
    int result = EINVAL;
    char *method;
    HandlerFunction fn = NULL;

    if ( ( pState != NULL ) &&
         ( pFCGIHandlers != NULL ) &&
         ( numHandlers > 0 ) )
    {
        /* wait for an FCGI request */
        while( FCGI_Accept() >= 0 )
        {
            /* check the request method */
            method = getenv("REQUEST_METHOD");
            if ( method != NULL )
            {
                /* get the handler associated with the method */
                fn = GetHandlerFunction( method, pFCGIHandlers, numHandlers );
                if ( fn != NULL )
                {
                    /* invoke the handler */
                    result = fn( pState );
                }
            }
        }
    }

    return result;
}

/*============================================================================*/
/*  GetHandlerFunction                                                        */
/*!
    Get the handler function for the specified method

    The GetHandlerFunction function looks up the processing function
    associated with the specified HTTP method.

    The handler functions are passed in via the pFCGIHandler pointer

    @param[in]
        method
            pointer to the method name, eg "GET", "POST"

    @param[in]
        pFCGIHandlers
            pointer to the FCGI method handling functions

    @param[in]
        numHandlers
            number of handlers in the method handling function array pointed
            to by pFCGIHandler

    @retval pointer to the method handler
    @retval NULL no method handler could be found

==============================================================================*/
static HandlerFunction GetHandlerFunction( char *method,
                                           FCGIHandler *pFCGIHandlers,
                                           size_t numHandlers )
{
    size_t i;
    FCGIHandler *pFCGIHandler;
    HandlerFunction fn = NULL;

    if ( ( method != NULL ) &&
         ( pFCGIHandlers != NULL ) &&
         ( numHandlers > 0 ) )
    {
        /* iterate through the FCGI method handlers */
        for ( i = 0; i < numHandlers ; i++ )
        {
            /* get a pointer to the current method handler */
            pFCGIHandler = &pFCGIHandlers[i];
            if ( pFCGIHandler != NULL )
            {
                /* check if it matches the REQUEST_METHOD or the
                 * wild card */
                if ( ( strcmp( pFCGIHandler->handler, method ) == 0 ) ||
                     ( strcmp( pFCGIHandler->handler, "*" ) == 0 ) )
                {
                    /* get a pointer to the handler function */
                    fn = pFCGIHandler->fn;
                    break;
                }
            }
        }
    }

    return fn;
}

/*============================================================================*/
/*  ProcessGETRequest                                                         */
/*!
    Process a Fast CGI GET request

    The ProcessGETRequest function processes a single FCGI GET request
    contained in the QUERY_STRING environment variable

    @param[in]
        pState
            pointer to the FCGIAuth state object

    @retval EOK request processed successfully
    @retval EINVAL invalid arguments

==============================================================================*/
static int ProcessGETRequest( FCGIAuthState *pState )
{
    int result = EINVAL;
    char *query;

    if ( pState != NULL )
    {
        /* get the query string */
        query = getenv("QUERY_STRING");

        /* process the request */
        result = ProcessQuery( pState, query );

    }
	else
	{
	    result = ErrorResponse( 400, "Bad request" );
	}

    return result;
}

/*============================================================================*/
/*  ProcessPOSTRequest                                                        */
/*!
    Process a Fast CGI POST request

    The ProcessPOSTRequest function processes a single FCGI POST request
    where the request is contained in the body of the message

    @param[in]
        pState
            pointer to the FCGIAuth state object

    @retval EOK request processed successfully
    @retval EINVAL invalid arguments

==============================================================================*/
static int ProcessPOSTRequest( FCGIAuthState *pState )
{
    int result = EINVAL;
    char *contentLength;
    size_t length;

    if ( pState != NULL )
    {
        /* get the content length */
        contentLength = getenv("CONTENT_LENGTH");
        if( contentLength != NULL )
        {
            /* convert the content length to an integer */
            length = strtoul(contentLength, NULL, 0);
            if ( ( length > 0 ) && ( length <= pState->maxPostLength ) )
            {
                /* read the query from the POST Data */
                result = GetPOSTData( pState, length );
                if( result == EOK )
                {
                    /* Process the request */
                    result = ProcessQuery( pState, pState->postBuffer );

                    /* clear the POST buffer.  This is critical since
                     * the buffer must be zeroed before the next read in order
                     * to make sure it is correctly NUL terminated */
                    ClearPOSTBuffer( pState );
                }
            }
            else
            {
                /* content length is too large (or too small) */
                ErrorResponse( 413, "Invalid Content-Length" );
            }
        }
        else
        {
            /* unable to get content length */
            ErrorResponse( 413, "Invalid Content-Length" );
        }
    }

    return result;
}

/*============================================================================*/
/*  GetPOSTData                                                               */
/*!
    Read the POST data from a Fast CGI POST request

    The GetPOSTData function reads the POST data into the POST data
    buffer in the FCGIAuthState object.  It is assumed that the
    content length has already been determined and is specified
    in the length parameter.

    Note that this function does NOT NUL terminate the input buffer.
    This buffer is assumed to be zeroed before each read

    @param[in]
        pState
            pointer to the FCGIAuth state object

    @param[in]
        length
            content-length bytes to read

    @retval EOK request processed successfully
    @retval ENXIO I/O error
    @retval ENOMEM not enough memory to read the POST data
    @retval EINVAL invalid arguments

==============================================================================*/
static int GetPOSTData( FCGIAuthState *pState, size_t length )
{
    int result = EINVAL;

    if ( pState != NULL )
    {
        if( length <= pState->maxPostLength )
        {
            /* read content-length bytes of data */
            if ( FCGI_fread( pState->postBuffer, length, 1, FCGI_stdin ) == 1 )
            {
                /* content-length bytes of data successfully read */
                result = EOK;
            }
            else
            {
                /* unable to read content-length bytes of data */
                result = ENXIO;
            }
        }
        else
        {
            /* not enough memory to read content-length bytes of data */
            result = ENOMEM;
        }
    }

    return result;
}

/*============================================================================*/
/*  ProcessUnsupportedRequest                                                 */
/*!
    Process a Fast CGI request using an unsupport request method

    The ProcessUnsupportedRequest function processes a single FCGI request
    where the request method is not supported

    @param[in]
        pState
            pointer to the FCGIAuth state object

    @retval EOK request processed successfully
    @retval EINVAL invalid arguments

==============================================================================*/
static int ProcessUnsupportedRequest( FCGIAuthState *pState )
{
    int result = EINVAL;

    if ( pState != NULL )
    {
        result = ErrorResponse( 405, "Method Not Allowed" );
    }

    return result;
}

/*============================================================================*/
/*  ProcessQuery                                                              */
/*!
    Process a Variable Query

    The ProcessQuery function processes a single variable query

    @param[in]
        pState
            pointer to the FCGIAuth state object

    @param[in]
        query
            pointer to the query

    @retval EOK query processed successfully
    @retval EINVAL invalid arguments

==============================================================================*/
static int ProcessQuery( FCGIAuthState *pState, char *query )
{
    int result = EINVAL;


    if ( query != NULL )
    {
        if ( strcmp( query, "login") ==  0 )
        {
            result = ProcessLoginQuery( pState, query );
        }
        else if ( strcmp( query, "logout" ) == 0 )
        {
            result = ProcessLogoutQuery( pState, query );
        }
        else
        {
    	    result = ErrorResponse( 400, "Bad request" );
        }
    }
    else
    {
	    result = ErrorResponse( 200, "test2" );
    }

    return result;
}

/*============================================================================*/
/*  ProcessLoginQuery                                                         */
/*!
    Process a login query

    The ProcessLoginQuery function processes the "login" request.

    @param[in]
        pState
            pointer to the FCGIAuth state object

    @param[in]
        query
            pointer to the query

    @retval EOK query processed successfully
    @retval EINVAL invalid arguments

==============================================================================*/
static int ProcessLoginQuery( FCGIAuthState *pState, char *query )
{
    int result = EINVAL;
    char *authorization;
    char *creds = NULL;
    char *p;
    char buf[BUFSIZ];
    char *username;
    char *password;
    char *reference;
    char session[SESSION_ID_LEN+1];

    if ( ( pState != NULL ) &&
         ( query != NULL ) )
    {
        creds = GetCreds( buf, BUFSIZ );
        reference = getenv("REMOTE_ADDR");

        if ( ( creds != NULL ) &&
             ( reference != NULL ) )
        {
            username = creds;
            p = strchr(creds, ':');
            if ( p != NULL )
            {
                *p = 0;
                password = p+1;
            }

            result = SESSIONMGR_NewSession( username,
                                            password,
                                            reference,
                                            session,
                                            sizeof(session) );
            if ( result == EOK )
            {
                result = AuthSessionResponse( session );
            }
            else
            {
                result = ErrorResponse( 401, "Unauthorized");
            }
        }
        else
        {
            result = ErrorResponse( 401, "Unauthorized");
        }
    }

    return result;
}

/*============================================================================*/
/*  GetCreds                                                                  */
/*!
    Get basic auth login credentials

    The GetCreds function extracts the basic auth login credentials
    from the HTTP_AUTHORIZATION header in the current request.

    @param[in,out]
        buf
            pointer to a buffer to store the decoded 'user:pass' credentials

    @param[in]
        len
            size of the buffer to store the credentials

    @retval pointer to the decoded credentials in the form user:pass
    @retval NULL if the credentials could not be decoded

==============================================================================*/
static char *GetCreds( char *buf, size_t len )
{
    char *authorization = NULL;
    char *creds = NULL;
    char *p = NULL;

    if ( ( buf != NULL ) &&
         ( len > 0 ) )
    {
        authorization = getenv( "HTTP_AUTHORIZATION");
        if ( authorization != NULL )
        {
            p = strstr( authorization, "Basic ");
            if ( p != NULL )
            {
                creds = p+6;
            }
            else
            {
                p = strstr( authorization, "basic ");
                if ( p != NULL )
                {
                    creds = p+6;
                }
            }

            if ( creds != NULL )
            {
                creds = base64_decode( creds, buf, len );
            }
        }
    }

    return creds;
}

/*============================================================================*/
/*  ProcessLogoutQuery                                                         */
/*!
    Process a logout query

    The ProcessLogoutQuery function processes the "logout" request.

    @param[in]
        pState
            pointer to the FCGIAuth state object

    @param[in]
        query
            pointer to the query

    @retval EOK query processed successfully
    @retval EINVAL invalid arguments

==============================================================================*/
static int ProcessLogoutQuery( FCGIAuthState *pState, char *query )
{
    int result = EINVAL;
    char *cookie;
    size_t len;
    char *p;
    char *start;
    char session[SESSION_ID_LEN+1];

    if ( ( pState != NULL ) &&
         ( query != NULL ) )
    {
        cookie = getenv("HTTP_COOKIE");
        if ( cookie != NULL )
        {
            p = strstr(cookie, "session=");
            if ( p != NULL )
            {
                p += 8;
            }

            start = p;
            p = strchr(start, ';');
            if ( p != NULL )
            {
                len = p - start;
            }
            else
            {
                len = strlen( start );
            }

            if ( len <= SESSION_ID_LEN )
            {
                memcpy( session, start, len );
                session[len] = 0;
            }

            result = SESSIONMGR_EndSession( session );
            if ( result == EOK )
            {
                printf("Status: 204 OK\r\n\r\n");
            }
            else
            {
                result = ErrorResponse( 401, "Unauthorized");
            }
        }
        else
        {
            result = ErrorResponse( 401, "Unauthorized");

        }
    }

    return result;
}

/*============================================================================*/
/*  AllocatePOSTBuffer                                                        */
/*!
    Allocate memory for the POST buffer

    The AllocatePOSTBuffer function allocates storage space on the heap
    for a buffer to contain the POST data.  It gets the requested POST
    buffer size from the FCGIAuthState object.

    @param[in]
        pState
            pointer to the FCGIAuth state object containing the requested
            POST buffer size

    @retval EOK memory was successfully allocated for the POST buffer
    @retval ENOMEM could not allocate memory for the POST buffer
    @retval EINVAL invalid arguments

==============================================================================*/
static int AllocatePOSTBuffer( FCGIAuthState *pState )
{
    int result = EINVAL;

    if ( pState != NULL )
    {
        if( pState->maxPostLength > 0 )
        {
            /* allocate memory for the POST buffer including a NUL terminator */
            pState->postBuffer = calloc( 1, pState->maxPostLength + 1 );
            if( pState->postBuffer != NULL )
            {
                result = EOK;
            }
            else
            {
                /* cannot allocate memory for the POST buffer */
                result = ENOMEM;
            }
        }
    }

    return result;
}

/*============================================================================*/
/*  ClearPOSTBuffer                                                           */
/*!
    Zero the memory used for the POST data

    The ClearPOSTBuffer function zeros the memory used by the POST buffer
    between requests.

    @param[in]
        pState
            pointer to the FCGIAuth state object containing the POST buffer.

    @retval EOK memory was successfully allocated for the POST buffer
    @retval ENOMEM the POST buffer memory was not allocated
    @retval EINVAL invalid arguments

==============================================================================*/
static int ClearPOSTBuffer( FCGIAuthState *pState )
{
    int result = EINVAL;

    if ( pState != NULL )
    {
        if ( pState->postBuffer != NULL )
        {
            /* clear the post buffer (including NUL terminator) */
            memset( pState->postBuffer, 0, pState->maxPostLength + 1 );

            result = EOK;
        }
        else
        {
            result = ENOMEM;
        }
    }

    return result;
}

/*============================================================================*/
/*  SetupTerminationHandler                                                   */
/*!
    Set up an abnormal termination handler

    The SetupTerminationHandler function registers a termination handler
    function with the kernel in case of an abnormal termination of this
    process.

==============================================================================*/
static void SetupTerminationHandler( void )
{
    static struct sigaction sigact;

    memset( &sigact, 0, sizeof(sigact) );

    sigact.sa_sigaction = TerminationHandler;
    sigact.sa_flags = SA_SIGINFO;

    sigaction( SIGTERM, &sigact, NULL );

}

/*============================================================================*/
/*  TerminationHandler                                                        */
/*!
    Abnormal termination handler

    The TerminationHandler function will be invoked in case of an abnormal
    termination of this process.  The termination handler closes
    the connection with the variable server and cleans up its VARFP shared
    memory.

@param[in]
    signum
        The signal which caused the abnormal termination (unused)

@param[in]
    info
        pointer to a siginfo_t object (unused)

@param[in]
    ptr
        signal context information (ucontext_t) (unused)

==============================================================================*/
static void TerminationHandler( int signum, siginfo_t *info, void *ptr )
{
    /* signum, info, and ptr are unused */
    (void)signum;
    (void)info;
    (void)ptr;

}

/*============================================================================*/
/*  ErrorResponse                                                             */
/*!
    Send an error response

    The ErrorResponse function sends an error response to the client
    using the Status header, and the status code and error description
    in a JSON object.

    @param[in]
        status
            status response code

    @param[in]
        description
            status response description

    @retval EOK the response was sent
    @retval EINVAL invalid arguments

==============================================================================*/
static int ErrorResponse( int status,  char *description )
{
    int result = EINVAL;

    if ( description != NULL )
    {
        /* output header */
        printf("Status: %d %s\r\n", status, description);
        printf("Content-Type: application/json\r\n\r\n");

        /* output body */
        printf("{\"status\": %d, \"description\" : \"%s\"}",
                status,
                description );

        result = EOK;

    }

    return result;
}

/*============================================================================*/
/*  AuthSessionResponse                                                       */
/*!
    Send an auth session response

    The AuthSessionResponse function sends an session response to the client
    with a header setting the session identifier in a cookie

    @param[in]
        session
            pointer to a session identifier

    @retval EOK the response was sent
    @retval EINVAL invalid arguments

==============================================================================*/
static int AuthSessionResponse( char *session )
{
    int result = EINVAL;

    if ( session != NULL )
    {
        /* output header */
        printf("Status: 200 OK\r\n");
        printf("Content-Type: application/json\r\n");
        printf("Set-Cookie: session=%s; Secure; HttpOnly\r\n", session);
        printf("\r\n");

        /* output body */
        printf("{\"session\": \"%s\" }\r\n", session );

        result = EOK;
    }

    return result;
}

/*============================================================================*/
/*  base64_decode                                                             */
/*!
    base64 decode an input buffer

    The base64_decode function does a base64 decoding of the input
    buffer and stores the decoded data in the output buffer.

    @param[in]
        cipher
            pointer to the input buffer to be decoded

    @param[in]
        plain
            pointer to an output buffer to store the decoded output

    @param[in]
        len
            length of the output buffer

    @retval pointer to the output buffer
    @retval NULL if an error occurred

==============================================================================*/
static char* base64_decode(char* cipher, char *plain, size_t len)
{
    char counts = 0;
    char buffer[4];
    int i = 0;
    int j = 0;
    char k;
    char *p = NULL;
    char c;

    static const char base46_map[] =
        {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
         'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
         'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
         'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
         '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'};

    if ( ( cipher != NULL ) &&
         ( plain != NULL ) &&
         ( len > 0 ) )
    {
        p = plain;

        while ( ( ( c = cipher[i++] ) != '\0' ) && ( j < len ))
        {
            for ( k = 0 ;  ( k < 64 ) && ( c != base46_map[k] ) ; k++);

            buffer[counts++] = k;

            if ( counts == 4 )
            {
                p[j++] = (buffer[0] << 2) + (buffer[1] >> 4);
                if (buffer[2] != 64)
                {
                    p[j++] = (buffer[1] << 4) + (buffer[2] >> 2);
                }

                if (buffer[3] != 64)
                {
                    p[j++] = (buffer[2] << 6) + buffer[3];
                }

                counts = 0;
            }
        }

        p[j++] = '\0';    /* string padding character */

    }

    return p;
}

/*! @>
 * end of fcgi_auth group */
