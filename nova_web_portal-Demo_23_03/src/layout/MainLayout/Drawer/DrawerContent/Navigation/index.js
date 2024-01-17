import { useState, useEffect } from 'react';

// material-ui
import { Box, Typography } from '@mui/material';
// project import
import NavGroup from './NavGroup';

import menuItem from '../../../../menu-items';
import serviceFactoryInstance from 'framework/services/service-factory';
// ==============================|| DRAWER CONTENT - NAVIGATION ||============================== //

const Navigation = () => {
    const [privileges, setPrivileges] = useState([]);
    useEffect(() => {
        console.log(menuItem.items);
        serviceFactoryInstance.authService.getUserObservable().subscribe((user) => {
            if (!user) {
                setPrivileges([]);
            } else {
                setPrivileges(user.privileges);
            }
        });
    }, []);

    const navGroups = menuItem.items.map((item) => {
        console.log('checking', item);
        if (serviceFactoryInstance.authService.hasPrivilege(item.privilege) || !item.privilege) {
            console.log('checking 2', item);
            switch (item.type) {
                case 'group':
                    return <NavGroup key={item.id} item={item} />;
                default:
                    return (
                        <Typography key={item.id} variant="h6" color="error" align="center">
                            Fix - Navigation Group
                        </Typography>
                    );
            }
        } else {
            return null;
        }
    });

    return <Box sx={{ pt: 2 }}>{navGroups}</Box>;
};

export default Navigation;
