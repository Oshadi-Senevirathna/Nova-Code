import { makeStyles } from '../../../node_modules/@mui/styles/index';
import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { ENTITY_NAME_USERS } from 'framework/caching/entity-cache';
import serviceFactoryInstance from 'framework/services/service-factory';
import configs from './user-config.json';
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

const UsersPage = ({ title }) => {
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
                .deleteInstance(ENTITY_NAME_USERS, UUID)
                .then((data) => {
                    if (data.status) {
                        setSuccessSnackbarMessage('Delete user successful');
                    } else {
                        setErrorSnackbarMessage('Delete user failed');
                    }
                })
                .catch((reason) => {
                    setErrorSnackbarMessage('Delete user failed');
                });
        }
    };

    return (
        <div className={classes.root}>
            <CustomSnackbar msg={successSnackbarMessage} onClose={() => setSuccessSnackbarMessage('')} severity="success" title="Success" />
            <CustomSnackbar msg={errorSnackbarMessage} onClose={() => setErrorSnackbarMessage('')} severity="error" title="Error" />
            <CustomDatatable
                entityName={ENTITY_NAME_USERS}
                configs={configs}
                deleteData={deleteData}
                navigateToPage={(UUID) => navigate(`/users/details/${UUID}`)}
            />
            <Grid item xs={12} marginTop={2}>
                <AnimateButton>
                    <Button
                        fullWidth
                        size="large"
                        variant="contained"
                        color="primary"
                        type="button"
                        onClick={() => navigate(`/users/details`)}
                    >
                        Add
                    </Button>
                </AnimateButton>
            </Grid>
        </div>
    );
};

export default UsersPage;
