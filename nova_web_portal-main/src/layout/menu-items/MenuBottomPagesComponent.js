import React from 'react';
import {
    LoginOutlined,
    ProfileOutlined,
    SettingOutlined,
    ReconciliationOutlined,
    UserOutlined,
    IdcardFilled,
    CarryOutOutlined,
    LaptopOutlined,
    UnorderedListOutlined,
    ContainerOutlined,
    ClockCircleOutlined,
    BankOutlined
} from '@ant-design/icons';
import { Menu } from '../../../node_modules/@mui/material/index';
// icons
const icons = {
    LoginOutlined,
    ProfileOutlined,
    SettingOutlined,
    ReconciliationOutlined,
    UserOutlined,
    CarryOutOutlined,
    IdcardFilled,
    LaptopOutlined,
    UnorderedListOutlined,
    ContainerOutlined,
    ClockCircleOutlined,
    BankOutlined
};

// ==============================|| MENU ITEMS - MENU BOTTOM PAGES ||============================== //
const menuBottomPages = {
    Id: 'menu-bottom-pages',
    title: 'Menu Bottom Pages',
    type: 'group',
    children: [
        {
            id: 'logs',
            title: 'Logs',
            type: 'item',
            url: '/logs',
            icon: icons.UnorderedListOutlined
        },
        {
            id: 'reports',
            title: 'Reports',
            type: 'item',
            url: '/reports',
            icon: icons.ContainerOutlined
        }
    ]
};

function MenuBottomPagesComponent() {
    return (
        <Menu mode="horizontal" theme="dark" style={{ position: 'fixed', bottom: 0, left: 0 }}>
            {menuBottomPages.children.map((item) => (
                <Menu.Item key={item.id} icon={<item.icon />}>
                    <a href={item.url}>{item.title}</a>
                </Menu.Item>
            ))}
        </Menu>
    );
}

export default MenuBottomPagesComponent;
