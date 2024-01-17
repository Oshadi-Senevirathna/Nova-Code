// assets
import { LaptopOutlined, ContainerOutlined } from '@ant-design/icons';
// icons
const icons = {
    LaptopOutlined,
    ContainerOutlined
};

// ==============================|| MENU ITEMS - EXTRA PAGES ||============================== //

const vnf = {
    id: 'vnf',
    title: 'VNF',
    type: 'group',
    privilege: 'manage_vnf',
    children: [
        {
            id: 'vm_images',
            title: 'VNF Images',
            type: 'item',
            url: '/vmimages',
            icon: icons.LaptopOutlined
        },
        {
            id: 'vm_templates',
            title: 'VNF Templates',
            type: 'item',
            url: '/vmtemplates',
            icon: icons.ContainerOutlined
        },
        {
            id: 'vm_templates_details',
            title: 'VNF Templates Details',
            type: 'crumb',
            url: '/vmtemplates/details',
            icon: icons.ContainerOutlined
        }
    ]
};

export default vnf;
