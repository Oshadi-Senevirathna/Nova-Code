// assets
import { UserOutlined, ControlOutlined } from '@ant-design/icons';
// icons
const icons = {
    UserOutlined,
    ControlOutlined
};

// ==============================|| MENU ITEMS - EXTRA PAGES ||============================== //

const users = {
    id: 'user',
    title: 'User',
    type: 'group',
    privilege: 'manage_users',
    children: [
        {
            id: 'roles',
            title: 'Roles',
            type: 'item',
            url: '/roles',
            icon: icons.ControlOutlined
        },
        {
            id: 'role_details',
            title: 'Role Details',
            type: 'crumb',
            url: '/roles/details',
            icon: icons.ControlOutlined
        },
        {
            id: 'users',
            title: 'Users',
            type: 'item',
            url: '/users',
            icon: icons.UserOutlined
        },
        {
            id: 'user_details',
            title: 'User Details',
            type: 'crumb',
            url: '/users/details',
            icon: icons.UserOutlined
        }
    ]
};

export default users;
