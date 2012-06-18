
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <casn.h>
#include <certificate.h>
#include <stdio.h>

char *msgs[] = {
    "Finished %s OK\n",
    "Usage: filename serialNum\n",
    "Can't open %s\n",
    "Error reading %n\n",
    "Error writing %s\n",
};

void fatal(
    int num,
    char *note)
{
    printf(msgs[num], note);
    if (num)
        exit(num);
}

int main(
    int argc,
    char **argv)
{
    struct Certificate cert;
    int certnum;
    Certificate(&cert, (ushort) 0);
    if (argc < 3)
        fatal(1, (char *)0);
    if (get_casn_file(&cert.self, argv[1], 0) <= 0)
        fatal(1, argv[1]);
    if (sscanf(argv[2], "%d", &certnum) != 1)
        fatal(2, "serial number");
    if (write_casn_num(&cert.toBeSigned.serialNumber, certnum) < 0)
        fatal(3, "serial number");
    if (put_casn_file(&cert.self, argv[1], 0) < 0)
        fatal(3, argv[1]);
    fatal(0, argv[1]);
    return 0;
}
