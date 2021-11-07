#include <utils/rule_db.h>
#include <assert.h>

int main() {
    rule_db rule_db;
    set_rule_db_path(&rule_db, "tests/test.db");
    delete_rule(&rule_db, 0);
//    show_rules(&rule_db);

    rule rule1; // OP_KILL
    create_rule(&rule1, OP_KILL, 1001, 0, "35626");
    add_rule(&rule_db, &rule1);

    rule rule2; // OP_WRITE
    create_rule(&rule2, OP_WRITE, 1000, 1001, "/home/zihan/a.txt");
    add_rule(&rule_db, &rule2);

    rule rule3; // OP_UNLINK
    create_rule(&rule3, OP_UNLINK, 1001, 1003, "/home/zihan/Desktop/b.c");
    add_rule(&rule_db, &rule3);

//    show_rules(&rule_db);

    delete_rule(&rule_db, 1);
//    show_rules(&rule_db);
    clear_rules(&rule_db);
//    show_rules(&rule_db);

    add_rule(&rule_db, &rule1);
    add_rule(&rule_db, &rule2);
    add_rule(&rule_db, &rule3);
//    show_rules(&rule_db);

    create_rule(&rule1, OP_KILL, 0, 1002, "35626");
    add_rule(&rule_db, &rule1);
    create_rule(&rule1, OP_WRITE, 1002, 0, "/home/zihan/a.txt");
    add_rule(&rule_db, &rule1);
    create_rule(&rule1, OP_UNLINK, 1002, 1004, "/home/zihan/Desktop/b.c");
    add_rule(&rule_db, &rule1);
    show_rules(&rule_db);

    kill_msg kill_msg;
    build_kill_msg(&kill_msg, 1000, 1002, 35625);
    assert(check_kill(&rule_db, &kill_msg) == 0);
    build_kill_msg(&kill_msg, 1000, 1001, 35626);
    assert(check_kill(&rule_db, &kill_msg) == 0);
    build_kill_msg(&kill_msg, 1000, 1002, 35626);
    assert(check_kill(&rule_db, &kill_msg) == 1);
    build_kill_msg(&kill_msg, 1001, 1000, 35626);
    assert(check_kill(&rule_db, &kill_msg) == 1);

    write_msg write_msg;
//    build_write_msg(&write_msg, 1000, 1001, "/home/zihan/a.c");
    build_write_msg(&write_msg, 1000, 1001, "/home/zihan/.a.c.swp");
    assert(check_write(&rule_db, &write_msg) == 0);
//    build_write_msg(&write_msg, 1000, 1001, "/home/zihan/a.txt");
    build_write_msg(&write_msg, 1000, 1001, "/home/zihan/.a.txt.swp");
    assert(check_write(&rule_db, &write_msg) == 1);
//    build_write_msg(&write_msg, 1000, 1002, "/home/zihan/a.txt");
    build_write_msg(&write_msg, 1000, 1002, "/home/zihan/.a.txt.swo");
    assert(check_write(&rule_db, &write_msg) == 0);
    build_write_msg(&write_msg, 1002, 1001, "/home/zihan/a.txt");
    assert(check_write(&rule_db, &write_msg) == 1);

    unlink_msg unlink_msg;
    build_unlink_msg(&unlink_msg, 1002, 1004, "/home/zihan/a.txt");
    assert(check_unlink(&rule_db, &unlink_msg) == 0);
    build_unlink_msg(&unlink_msg, 1001, 1004, "/home/zihan/Desktop/b.c");
    assert(check_unlink(&rule_db, &unlink_msg) == 0);
    build_unlink_msg(&unlink_msg, 1002, 1004, "/home/zihan/Desktop/b.c");
    assert(check_unlink(&rule_db, &unlink_msg) == 1);
    build_unlink_msg(&unlink_msg, 1001, 1003, "/home/zihan/Desktop/b.c");
    assert(check_unlink(&rule_db, &unlink_msg) == 1);

    return 0;
}

