import PropTypes from 'prop-types';
import { useEffect, useState } from 'react';
import { Link, useLocation } from 'react-router-dom';
// material-ui
import MuiBreadcrumbs from '@mui/material/Breadcrumbs';
import { Grid, Typography } from '@mui/material';
// project imports
import MainCard from '../MainCard';

// ==============================|| BREADCRUMBS ||============================== //

const Breadcrumbs = ({ navigation, ...others }) => {
    const location = useLocation();
    const [main, setMain] = useState();
    const [item, setItem] = useState();
    const [items, setItems] = useState([]);

    // set active item state
    const getCollapse = (menu) => {
        if (menu.children) {
            var temp = [];
            menu.children.forEach((collapse) => {
                if (collapse.type && (collapse.type === 'item' || collapse.type === 'crumb')) {
                    if (location.pathname.includes(collapse.url)) {
                        setMain(menu);
                        setItem(collapse);
                        temp.push(collapse);
                        return true;
                    }
                }
            });
            if (temp.length > 0) {
                setItems(temp);
            }
        }
    };

    useEffect(() => {
        navigation?.items?.map((menu) => {
            if (menu.type && menu.type === 'group') {
                getCollapse(menu);
            }
            return false;
        });
    }, [location.pathname]);

    // only used for component demo breadcrumbs
    if (location.pathname === '/breadcrumbs') {
        location.pathname = '/dashboard/analytics';
    }

    let mainContent;
    let itemContent;
    let breadcrumbContent = <Typography />;
    let itemTitle = '';

    // collapse item
    if (main && main.type === 'collapse') {
        mainContent = (
            <Typography component={Link} to={document.location.pathname} variant="h6" sx={{ textDecoration: 'none' }} color="textSecondary">
                {main.title}
            </Typography>
        );
    }

    // items
    if (item && (item.type === 'item' || item.type === 'crumb')) {
        itemTitle = item.title;
        itemContent = (
            <Typography variant="subtitle1" color="textPrimary">
                {itemTitle}
            </Typography>
        );

        // main
        if (item.breadcrumbs !== false) {
            breadcrumbContent = (
                <MainCard border={false} sx={{ mb: 3, bgcolor: 'transparent' }} {...others} content={false}>
                    <Grid container direction="column" justifyContent="flex-start" alignItems="flex-start" spacing={1}>
                        <Grid item>
                            <MuiBreadcrumbs aria-label="breadcrumb">
                                <Typography component={Link} to="/" color="textSecondary" variant="h6" sx={{ textDecoration: 'none' }}>
                                    Home
                                </Typography>

                                {items &&
                                    items.map((itemT) => {
                                        if (itemT === items[items.length - 1]) {
                                            return (
                                                <Typography key={itemT.title} variant="subtitle1" color="textPrimary">
                                                    {itemT.title}
                                                </Typography>
                                            );
                                        } else {
                                            return (
                                                <Typography
                                                    component={Link}
                                                    key={itemT.title}
                                                    to={itemT.url}
                                                    variant="h6"
                                                    color="textSecondary"
                                                    sx={{ textDecoration: 'none' }}
                                                >
                                                    {itemT.title}
                                                </Typography>
                                            );
                                        }
                                    })}
                            </MuiBreadcrumbs>
                        </Grid>
                    </Grid>
                </MainCard>
            );
        }
    }

    return breadcrumbContent;
};

Breadcrumbs.propTypes = {
    navigation: PropTypes.object
};

export default Breadcrumbs;
