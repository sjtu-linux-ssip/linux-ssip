#include <utils/message.h>
#include <assert.h>

int main() {
    char buf[256];

    // kill
    kill_msg kill_msg_1;
    build_kill_msg(&kill_msg_1, 1000, 1001, 35625);
    kill2raw(buf, &kill_msg_1);
    assert(!strcmp(buf, "1000&1001&35625"));
    kill_msg kill_msg_2;
    raw2kill(buf, &kill_msg_2);
    assert(kill_msg_1.uid == kill_msg_2.uid);
    assert(kill_msg_1.gid == kill_msg_2.gid);
    assert(kill_msg_1.pid == kill_msg_2.pid);

    // write
    write_msg write_msg_1;
    build_write_msg(&write_msg_1, 1000, 1001, "/home/zihan/a.txt");
    write2raw(buf, &write_msg_1);
    assert(!strcmp(buf, "1000@1001@/home/zihan/a.txt"));
    write_msg write_msg_2;
    raw2write(buf, &write_msg_2);
    assert(write_msg_1.uid == write_msg_2.uid);
    assert(write_msg_1.gid == write_msg_2.gid);
    assert(!strcmp(write_msg_1.filename, write_msg_2.filename));

    // unlink
    unlink_msg unlink_msg_1;
    build_unlink_msg(&unlink_msg_1, 1000, 1001, "/home/zihan/a.txt");
    unlink2raw(buf, &unlink_msg_1);
    assert(!strcmp(buf, "1000#1001#/home/zihan/a.txt"));
    unlink_msg unlink_msg_2;
    raw2unlink(buf, &unlink_msg_2);
    assert(unlink_msg_1.uid == unlink_msg_2.uid);
    assert(unlink_msg_1.gid == unlink_msg_2.gid);
    assert(!strcmp(unlink_msg_1.filename, unlink_msg_2.filename));

    return 0;
}
