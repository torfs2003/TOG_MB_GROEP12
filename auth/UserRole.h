#ifndef USERROLE_H
#define USERROLE_H

enum UserRole {
    ROLE_CLIENT,    // R   (Read Only)
    ROLE_EMPLOYEE,  // RW  (Read + Write Data)
    ROLE_ADMIN      // RWX (Read + Write + Execute/DDL)
};

#endif //USERROLE_H
