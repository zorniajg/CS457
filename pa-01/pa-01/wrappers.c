/*-------------------------------------------------------------------------------
Written By: 
     1- Dr. Mohamed Aboutabl
Submitted on: 
-------------------------------------------------------------------------------*/
#include "wrappers.h"

///--------------------------------------------------------------------------
pid_t Fork(void) 
{
    pid_t pid;

    if ( (pid = fork() ) < 0)
    {
	    perror("Fork error");
        exit( -1 ) ;
    }
    return pid;
}

//--------------------------------------------------------------------------
int  Pipe( int fdArr[2] ) 
{
	int result ;
	
	result = pipe( fdArr ) ;
	if ( result == -1 ) 
    {
        perror( "Pipe failed" ) ;
        exit(-1) ;		;
    }
    return result ;    
}


