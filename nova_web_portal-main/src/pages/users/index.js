import { makeStyles } from '../../../node_modules/@mui/styles/index';
import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { ENTITY_NAME_USERS } from 'framework/caching/entity-cache';
import serviceFactoryInstance from 'framework/services/service-factory';
import configs from './user-config.json';
import MUIDataTable from 'mui-datatables';
import ConfirmationDialog from 'components/styledMUI/confirmation-dialog';
import { Button, Grid } from '@mui/material';
import AnimateButton from 'components/@extended/AnimateButton';

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
    const [users, setUsers] = useState([]);
    const navigate = useNavigate();
    const [deleteUUIDS, setDeleteUUIDS] = useState([]);
    const [confirmDeleteForm, setConfirmDeleteForm] = useState(false);

    useEffect(() => {
        document.title = title;
    }, []);

    useEffect(() => {
        const usersSub = serviceFactoryInstance.dataLoaderService.dataSub(ENTITY_NAME_USERS).subscribe((data) => {
            if (data) {
                setUsers(data);
            }
        });
        return () => {
            usersSub.unsubscribe();
        };
    }, [serviceFactoryInstance.cache]);

    const deleteData = (rows) => {
        for (let i = 0; i < rows.length; i++) {
            const UUID = rows[i];
            serviceFactoryInstance.dataLoaderService
                .deleteInstance(ENTITY_NAME_USERS, UUID)
                .then((data) => {
                    if (data.status) {
                        console.debug('Delete user successful');
                    } else {
                        console.debug('Delete user failed');
                    }
                })
                .catch((reason) => {
                    console.debug('Delete user failed');
                });
        }
    };

    const handleDeleteOK = () => {
        deleteData(deleteUUIDS);
        setConfirmDeleteForm(false);
    };

    const handleDeleteCancel = () => {
        setConfirmDeleteForm(false);
    };

    const options = {
        onRowsDelete: (rowsDeleted, dataRows) => {
            const rowsDeleteUUIDS = [];
            for (let i = 0; i < rowsDeleted.data.length; i++) {
                rowsDeleteUUIDS.push(users[rowsDeleted.data[i].dataIndex].UUID);
            }
            setDeleteUUIDS(rowsDeleteUUIDS);
            setConfirmDeleteForm(true);
        },
        filter: false,
        onRowClick: (rowData, rowMeta) => {
            navigate(`/users/details/${users[rowMeta.dataIndex].UUID}`);
        }
    };

    return (
        <div className={classes.root}>
            <ConfirmationDialog
                open={confirmDeleteForm}
                title="Delete Confirmation"
                message={
                    (deleteUUIDS.length > 1 && `Are you sure you want to delete the users?`) ||
                    (deleteUUIDS.length === 1 && `Are you sure you want to delete the user?`)
                }
                onOK={handleDeleteOK}
                onCancel={handleDeleteCancel}
            />
            <MUIDataTable options={options} data={users} columns={configs.fields} />
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
