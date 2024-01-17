// assets
import { IdcardFilled, BankOutlined } from '@ant-design/icons';
// icons
const icons = {
    IdcardFilled,
    BankOutlined
};

// ==============================|| MENU ITEMS - EXTRA PAGES ||============================== //

const companies = {
    id: 'company',
    title: 'Company',
    type: 'group',
    privilege: 'manage_companies',
    children: [
        {
            id: 'tenants',
            title: 'Tenants',
            type: 'item',
            url: '/tenants',
            icon: icons.IdcardFilled
        },
        {
            id: 'company',
            title: 'Companies',
            type: 'item',
            url: '/companies',
            icon: icons.BankOutlined
        }
    ]
};

export default companies;
