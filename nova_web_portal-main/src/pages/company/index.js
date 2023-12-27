import { makeStyles } from '../../../node_modules/@mui/styles/index';
import { Button, Grid } from '@mui/material';
import { ENTITY_NAME_COMPANY } from 'framework/caching/entity-cache';
import serviceFactoryInstance from 'framework/services/service-factory';
import MUIDataTable from 'mui-datatables';
import { useEffect, useState } from 'react';
import ConfirmationDialog from 'components/styledMUI/confirmation-dialog';
import configs from './company-config.json';
import CompanyForm from './company-form';
import CustomSnackbar from 'components/styledMUI/Snackbar';
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

const CompanyPage = ({ title }) => {
    const classes = useStyles();
    const [companies, setCompanies] = useState([]);
    const [UUID, setUUID] = useState();
    const [formOpen, setFormOpen] = useState(false);
    const [deleteUUIDS, setDeleteUUIDS] = useState([]);
    const [confirmDeleteForm, setConfirmDeleteForm] = useState(false);
    const [noOfInstances, setNoOfInstances] = useState(10);
    const [startOfInstances, setStartOfInstances] = useState(0);
    const [companiesCount, setCompaniesCount] = useState(0);
    const [page, setPage] = useState(0);
    const [errorSnackbarMessage, setErrorSnackbarMessage] = useState('');
    const [successSnackbarMessage, setSuccessSnackbarMessage] = useState('');

    useEffect(() => {
        document.title = title;
    }, []);

    var configReshaped = configs;

    useEffect(() => {
        const companiesSub = serviceFactoryInstance.dataLoaderService
            .dataSub(ENTITY_NAME_COMPANY, undefined, noOfInstances, startOfInstances)
            .subscribe((data) => {
                if (data) {
                    setCompanies(data);
                }
            });

        return () => {
            companiesSub.unsubscribe();
        };
    }, [serviceFactoryInstance.cache, noOfInstances, startOfInstances]);

    useEffect(() => {
        const companiesCountSub = serviceFactoryInstance.dataLoaderService.countSub(ENTITY_NAME_COMPANY).subscribe((data) => {
            if (data) {
                setCompaniesCount(data);
            }
        });

        return () => {
            companiesCountSub.unsubscribe();
        };
    }, [serviceFactoryInstance.cache]);

    const closeForm = () => {
        setUUID();
        setFormOpen(false);
    };

    const openForm = () => {
        setFormOpen(true);
    };

    const deleteData = (rows) => {
        for (let i = 0; i < rows.length; i++) {
            const UUID = rows[i];
            serviceFactoryInstance.dataLoaderService
                .deleteInstance(ENTITY_NAME_COMPANY, UUID)
                .then((data) => {
                    if (data.status) {
                        setSuccessSnackbarMessage('Delete company successful');
                    } else {
                        setErrorSnackbarMessage('Delete company failed');
                    }
                })
                .catch((reason) => {
                    setErrorSnackbarMessage('Delete company failed');
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
                rowsDeleteUUIDS.push(companies[rowsDeleted.data[i].dataIndex].UUID);
            }
            setDeleteUUIDS(rowsDeleteUUIDS);
            setConfirmDeleteForm(true);
        },
        onRowClick: (rowData, rowMeta) => {
            setUUID(companies[rowMeta.dataIndex].UUID);
            openForm();
        },
        count: companiesCount,
        rowsPerPage: 10,
        rowsPerPageOptions: [10, 25, 50],
        serverSide: true,
        page: page,
        filter: false,
        onChangePage(currentPage) {
            setPage(currentPage);
            setStartOfInstances(currentPage * noOfInstances);
        },
        onChangeRowsPerPage(numberOfRows) {
            setPage(0);
            setStartOfInstances(0);
            setNoOfInstances(numberOfRows);
        }
    };

    return (
        <div className={classes.root}>
            <ConfirmationDialog
                open={confirmDeleteForm}
                title="Delete Confirmation"
                message={
                    (deleteUUIDS.length > 1 && `Are you sure you want to delete the companies?`) ||
                    (deleteUUIDS.length === 1 && `Are you sure you want to delete the company?`)
                }
                onOK={handleDeleteOK}
                onCancel={handleDeleteCancel}
            />
            <CustomSnackbar msg={successSnackbarMessage} onClose={() => setSuccessSnackbarMessage('')} severity="success" title="Success" />
            <CustomSnackbar msg={errorSnackbarMessage} onClose={() => setErrorSnackbarMessage('')} severity="error" title="Error" />

            <MUIDataTable options={options} data={companies} columns={configReshaped.fields} />
            <CompanyForm
                formOpen={formOpen}
                closeForm={closeForm}
                UUID={UUID}
                setSuccessSnackbarMessage={(msg) => setSuccessSnackbarMessage(msg)}
                setErrorSnackbarMessage={(msg) => setErrorSnackbarMessage(msg)}
            />
            <Grid item xs={12} marginTop={2}>
                <AnimateButton>
                    <Button fullWidth size="large" variant="contained" color="primary" type="button" onClick={() => openForm()}>
                        Add
                    </Button>
                </AnimateButton>
            </Grid>
        </div>
    );
};

export default CompanyPage;
