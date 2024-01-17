import { makeStyles } from '../../../node_modules/@mui/styles/index';
import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { ENTITY_NAME_USER_ROLES } from 'framework/caching/entity-cache';
import serviceFactoryInstance from 'framework/services/service-factory';
import configs from './role-config.json';
import { Button, Grid } from '@mui/material';
import AnimateButton from 'components/@extended/AnimateButton';
import CustomDatatable from 'components/styledMUI/Datatable';
import CustomSnackbar from 'components/styledMUI/Snackbar';

const useStyles = makeStyles((theme) => ({
    root: {
        flexGrow: 1,
        width: '100%',
        margin: 0,
        padding: 0
    },
    progressBar: {
        marginTop: '20px',
        marginBottom: '20px',
        marginRight: '20px'
    },
    button: {
        marginRight: '20px',
        marginTop: '10px',
        width: '120px'
    },
    iconbutton: {
        marginRight: '20px',
        marginTop: '10px',
        width: '30px'
    }
}));

const RolesPage = ({ title }) => {
    const classes = useStyles();
    const navigate = useNavigate();
    const [errorSnackbarMessage, setErrorSnackbarMessage] = useState('');
    const [successSnackbarMessage, setSuccessSnackbarMessage] = useState('');

    useEffect(() => {
        document.title = title;
    }, []);

    const deleteData = (rows) => {
        for (let i = 0; i < rows.length; i++) {
            const UUID = rows[i];
            serviceFactoryInstance.dataLoaderService
                .deleteInstance(ENTITY_NAME_USER_ROLES, UUID)
                .then((data) => {
                    if (data.status) {
                        setSuccessSnackbarMessage('Delete role successful');
                    } else {
                        setErrorSnackbarMessage('Delete role failed');
                    }
                })
                .catch((reason) => {
                    setErrorSnackbarMessage('Delete role failed');
                });
        }
    };

    return (
        <div className={classes.root}>
            <CustomSnackbar msg={successSnackbarMessage} onClose={() => setSuccessSnackbarMessage('')} severity="success" title="Success" />
            <CustomSnackbar msg={errorSnackbarMessage} onClose={() => setErrorSnackbarMessage('')} severity="error" title="Error" />
            <CustomDatatable
                entityName={ENTITY_NAME_USER_ROLES}
                configs={configs}
                deleteData={deleteData}
                navigateToPage={(UUID) => navigate(`/roles/details/${UUID}`)}
            />
            <Grid item xs={12} marginTop={2}>
                <AnimateButton>
                    <Button
                        fullWidth
                        size="large"
                        variant="contained"
                        color="primary"
                        type="button"
                        onClick={() => navigate(`/roles/details`)}
                    >
                        Add
                    </Button>
                </AnimateButton>
            </Grid>
        </div>
    );
};

export default RolesPage;
