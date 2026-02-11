export const UserRolesEnum = {
    ADMIN: 'admin',
    USER: 'user',
}

export const AvailableUserRole = Object.values(UserRolesEnum);
export const DEFAULT_USER_ROLE = UserRolesEnum.USER;