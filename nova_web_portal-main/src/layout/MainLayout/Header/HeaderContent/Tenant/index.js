import PropTypes from 'prop-types';
import { useRef, useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import serviceFactoryInstance from 'framework/services/service-factory';
// material-ui
import { useTheme } from '@mui/material/styles';
import {
    Box,
    ButtonBase,
    CardContent,
    ClickAwayListener,
    Grid,
    Paper,
    Popper,
    Stack,
    Typography,
    List,
    ListItemButton,
    ListItemText
} from '@mui/material';
// project import
import MainCard from 'components/MainCard';
import Transitions from 'components/@extended/Transitions';
// assets
import { FilterFilled } from '@ant-design/icons';
import { ENTITY_NAME_TENANT } from 'framework/caching/entity-cache';

// tab panel wrapper
function TabPanel({ children, value, index, ...other }) {
    return (
        <div role="tabpanel" hidden={value !== index} id={`profile-tabpanel-${index}`} aria-labelledby={`profile-tab-${index}`} {...other}>
            {value === index && children}
        </div>
    );
}

TabPanel.propTypes = {
    children: PropTypes.node,
    index: PropTypes.any.isRequired,
    value: PropTypes.any.isRequired
};

function a11yProps(index) {
    return {
        id: `profile-tab-${index}`,
        'aria-controls': `profile-tabpanel-${index}`
    };
}

// ==============================|| HEADER CONTENT - PROFILE ||============================== //

const Tenant = () => {
    const theme = useTheme();
    const navigate = useNavigate();
    const [tenant, setTenant] = useState();
    const [tenants, setTenants] = useState([]);

    useEffect(() => {
        const tenantsSub = serviceFactoryInstance.dataLoaderService.dataSub(ENTITY_NAME_TENANT).subscribe((data) => {
            if (data) {
                var allTenant = {};
                allTenant.instance_name = 'All';
                allTenant.UUID = 0;
                const tempTenantList = data;
                tempTenantList.push(allTenant);

                setTenant(allTenant);
                serviceFactoryInstance.authService.setTenant(allTenant);

                setTenants(tempTenantList);
            }
        });

        return () => {
            tenantsSub.unsubscribe();
        };
    }, [serviceFactoryInstance.cache]);

    const handleSelect = (tenantSelect) => {
        setTenant(tenantSelect);
        serviceFactoryInstance.authService.setTenant(tenantSelect);
        setOpen(false);
    };

    const anchorRef = useRef(null);
    const [open, setOpen] = useState(false);
    const handleToggle = () => {
        setOpen((prevOpen) => !prevOpen);
    };

    const handleClose = (event) => {
        if (anchorRef.current && anchorRef.current.contains(event.target)) {
            return;
        }
        setOpen(false);
    };

    const iconBackColorOpen = 'grey.300';

    return (
        <Box sx={{ flexShrink: 0, ml: 0.75 }}>
            <ButtonBase
                sx={{
                    p: 0.25,
                    bgcolor: 'secondary.lighter',
                    borderRadius: 1,
                    '&:hover': { bgcolor: 'secondary.light' }
                }}
                aria-label="open profile"
                ref={anchorRef}
                aria-controls={open ? 'profile-grow' : undefined}
                aria-haspopup="true"
                onClick={handleToggle}
            >
                <Stack direction="row" spacing={2} alignItems="center" sx={{ p: 0.5 }}>
                    <FilterFilled />
                    {tenant ? (
                        <Typography variant="subtitle1">Tenant : {tenant.instance_name}</Typography>
                    ) : (
                        <Typography variant="subtitle1">Loading tenant</Typography>
                    )}
                </Stack>
            </ButtonBase>
            <Popper
                placement="bottom-end"
                open={open}
                anchorEl={anchorRef.current}
                role={undefined}
                transition
                disablePortal
                popperOptions={{
                    modifiers: [
                        {
                            name: 'offset',
                            options: {
                                offset: [0, 9]
                            }
                        }
                    ]
                }}
            >
                {({ TransitionProps }) => (
                    <Transitions type="fade" in={open} {...TransitionProps}>
                        {open && (
                            <Paper
                                sx={{
                                    boxShadow: theme.customShadows.z1,
                                    width: 290,
                                    minWidth: 240,
                                    maxWidth: 290,
                                    [theme.breakpoints.down('md')]: {
                                        maxWidth: 250
                                    }
                                }}
                            >
                                <ClickAwayListener onClickAway={handleClose}>
                                    <MainCard elevation={0} border={false} content={false}>
                                        <CardContent sx={{ px: 2.5, pt: 3 }}>
                                            <Grid container justifyContent="space-between" alignItems="center">
                                                <Grid item>
                                                    <Stack direction="row" spacing={1.25} alignItems="center">
                                                        <Stack>
                                                            <Typography style={{ fontWeight: 'bold' }}>Select a tenant to view</Typography>
                                                        </Stack>
                                                    </Stack>
                                                </Grid>
                                            </Grid>
                                        </CardContent>
                                        <>
                                            <List
                                                component="nav"
                                                sx={{
                                                    p: 0,
                                                    '& .MuiListItemIcon-root': { minWidth: 32, color: theme.palette.grey[500] }
                                                }}
                                            >
                                                {tenants && (
                                                    <>
                                                        {tenants.map((tenantSelect) => {
                                                            return (
                                                                <ListItemButton
                                                                    key={tenantSelect.UUID}
                                                                    onClick={() => handleSelect(tenantSelect)}
                                                                >
                                                                    <ListItemText primary={tenantSelect.instance_name} />
                                                                </ListItemButton>
                                                            );
                                                        })}
                                                    </>
                                                )}
                                            </List>
                                        </>
                                    </MainCard>
                                </ClickAwayListener>
                            </Paper>
                        )}
                    </Transitions>
                )}
            </Popper>
        </Box>
    );
};

export default Tenant;
