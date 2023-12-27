import { makeStyles } from '../../../node_modules/@mui/styles/index';
import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { ENTITY_NAME_VM_TEMPLATES } from 'framework/caching/entity-cache';
import serviceFactoryInstance from 'framework/services/service-factory';
import configs from './vm-template-config.json';
import MUIDataTable from 'mui-datatables';
import ConfirmationDialog from 'components/styledMUI/confirmation-dialog';
import { Button } from '../../../node_modules/@mui/material/index';
import { Grid } from '../../../node_modules/@mui/material/index';
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

const VMTemplatePage = ({ title }) => {
    const classes = useStyles();
    const [vmTemplates, setVmTemplates] = useState([]);
    const navigate = useNavigate();
    const [deleteUUIDS, setDeleteUUIDS] = useState([]);
    const [confirmDeleteForm, setConfirmDeleteForm] = useState(false);
    const [errorSnackbarMessage, setErrorSnackbarMessage] = useState('');
    const [successSnackbarMessage, setSuccessSnackbarMessage] = useState('');

    useEffect(() => {
        document.title = title;
    }, []);

    useEffect(() => {
        const vmTemplatesSub = serviceFactoryInstance.dataLoaderService.dataSub(ENTITY_NAME_VM_TEMPLATES).subscribe((data) => {
            if (data) {
                setVmTemplates(data);
            }
        });
        return () => {
            vmTemplatesSub.unsubscribe();
        };
    }, [serviceFactoryInstance.cache]);

    const deleteData = (rows) => {
        for (let i = 0; i < rows.length; i++) {
            const UUID = rows[i];
            serviceFactoryInstance.dataLoaderService
                .deleteInstance(ENTITY_NAME_VM_TEMPLATES, UUID)
                .then((data) => {
                    if (data.status) {
                        setSuccessSnackbarMessage('Delete vm template successful');
                    } else {
                        setErrorSnackbarMessage('Delete vm template failed');
                    }
                })
                .catch((reason) => {
                    setErrorSnackbarMessage('Delete vm template failed');
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
                rowsDeleteUUIDS.push(vmTemplates[rowsDeleted.data[i].dataIndex].UUID);
            }
            setDeleteUUIDS(rowsDeleteUUIDS);
            setConfirmDeleteForm(true);
        },
        onRowClick: (rowData, rowMeta) => {
            navigate(`/vmtemplates/details/${vmTemplates[rowMeta.dataIndex].UUID}`);
        },
        filter: false
        /* count: count,
        rowsPerPage: 10,
        rowsPerPageOptions: [10, 25, 50],
        serverSide: true,
        page: page,
        onChangePage(currentPage) {
            setPage(currentPage);
            setStartOfInstances(currentPage * noOfInstances);
        },
        onChangeRowsPerPage(numberOfRows) {
            setPage(0);
            setStartOfInstances(0);
            setNoOfInstances(numberOfRows);
        } */
    };

    return (
        <div className={classes.root}>
            <ConfirmationDialog
                open={confirmDeleteForm}
                title="Delete Confirmation"
                message={
                    (deleteUUIDS.length > 1 && `Are you sure you want to delete the vm templates?`) ||
                    (deleteUUIDS.length === 1 && `Are you sure you want to delete the vm template?`)
                }
                onOK={handleDeleteOK}
                onCancel={handleDeleteCancel}
            />
            <CustomSnackbar msg={successSnackbarMessage} onClose={() => setSuccessSnackbarMessage('')} severity="success" title="Success" />
            <CustomSnackbar msg={errorSnackbarMessage} onClose={() => setErrorSnackbarMessage('')} severity="error" title="Error" />
            <MUIDataTable options={options} data={vmTemplates} columns={configs.fields} />
            <Grid container style={{ justifyItems: 'center' }}>
                <Grid item xs={12} style={{ padding: 20 }}>
                    <Button size="medium" fullWidth variant="contained" color="primary" onClick={() => navigate(`/vmtemplates/details`)}>
                        Add VNF template
                    </Button>
                </Grid>
            </Grid>
        </div>
    );
};

export default VMTemplatePage;
