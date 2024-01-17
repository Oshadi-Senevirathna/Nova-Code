import { Box, Toolbar, useMediaQuery } from '@mui/material';
import { useTheme } from '@mui/material/styles';
import Breadcrumbs from 'components/@extended/Breadcrumbs';
import { useEffect, useState } from 'react';
import { useDispatch, useSelector } from 'react-redux';
import { Outlet } from 'react-router-dom';
import { openDrawer } from 'store/reducers/menu';

import menuItem from 'layout/menu-items/index';
import navigation from '../menu-items';
import Drawer from './Drawer';
import Header from './Header';
import serviceFactoryInstance from 'framework/services/service-factory';

// ==============================|| MAIN LAYOUT ||============================== //

const MainLayout = () => {
    const theme = useTheme();
    const matchDownLG = useMediaQuery(theme.breakpoints.down('xl'));
    const dispatch = useDispatch();

    const { drawerOpen } = useSelector((state) => state.menu);

    // drawer toggler
    const [open, setOpen] = useState(drawerOpen);
    const handleDrawerToggle = () => {
        setOpen(!open);
        dispatch(openDrawer({ drawerOpen: !open }));
    };

    // set media wise responsive drawer
    useEffect(() => {
        setOpen(!matchDownLG);
        dispatch(openDrawer({ drawerOpen: !matchDownLG }));

        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [matchDownLG]);

    useEffect(() => {
        if (open !== drawerOpen) setOpen(drawerOpen);
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [drawerOpen]);

    const [privileges, setPrivileges] = useState([]);
    useEffect(() => {
        serviceFactoryInstance.authService.getUserObservable().subscribe((user) => {
            if (!user) {
                setPrivileges([]);
            } else {
                setPrivileges(user.privileges);
            }
        });
    }, []);

    const filteredMenuItems = () => {
        return {
            items: menuItem.items.filter((item) => {
                return serviceFactoryInstance.authService.hasPrivilege(item.privilege) || !item.privilege;
            })
        };
    };

    return (
        <Box sx={{ display: 'flex', width: '100%' }}>
            <Header open={open} handleDrawerToggle={handleDrawerToggle} />
            <Drawer open={open} handleDrawerToggle={handleDrawerToggle} />
            <Box component="main" sx={{ width: '100%', flexGrow: 1, p: { xs: 2, sm: 3 } }}>
                <Toolbar />
                <Breadcrumbs navigation={filteredMenuItems()} divider={false} />
                <Outlet />
            </Box>
        </Box>
    );
};

export default MainLayout;
