import { useState, useEffect } from 'react';
import serviceFactoryInstance from 'framework/services/service-factory';
import ConfirmationDialog from './confirmation-dialog';
import MUIDataTable from 'mui-datatables';
import { CSVLink } from 'react-csv';
import Summary from './summary';
import { FilterFilled } from '@ant-design/icons';
import { Box, Popover, ButtonBase, Stack, Paper, List, ListItemButton, ListItemText, Typography } from '@mui/material';

// project import
// assets

// ==============================|| SNACKBAR ||============================== //

const CustomDatatable = ({
    entityName,
    tenant,
    configs,
    deleteData,
    setUUID,
    openForm,
    summary,
    filter,
    navigateToPage,
    presetFilterValue
}) => {
    const [confirmDeleteForm, setConfirmDeleteForm] = useState(false);
    const [deleteUUIDS, setDeleteUUIDS] = useState([]);
    const [noOfInstances, setNoOfInstances] = useState(10);
    const [startOfInstances, setStartOfInstances] = useState(0);
    const [count, setCount] = useState(0);
    const [page, setPage] = useState(0);
    const [data, setData] = useState([]);
    const [queryString, setQueryString] = useState('');
    const [queryStringTemp, setQueryStringTemp] = useState('');
    const [filterField, setFilterField] = useState();
    const [filterValues, setFilterValues] = useState();
    const [filterValue, setFilterValue] = useState();
    const [sortField, setSortField] = useState();
    const [sortDirection, setSortDirection] = useState();
    const [downloadData, setDownloadData] = useState([]);
    const downloadConfigs = [];
    const fields = [];

    for (let i = 0; i < configs.fields.length; i++) {
        fields.push(`"${configs.fields[i].name}"`);
        downloadConfigs.push({ ...configs.fields[i], key: configs.fields[i].name });
    }

    useEffect(() => {
        for (let i = 0; i < configs.fields.length; i++) {
            if (configs.fields[i].options && configs.fields[i].options.filter === true) {
                setFilterField(configs.fields[i]);
            }
        }
    }, []);

    useEffect(() => {
        if (filterField) {
            serviceFactoryInstance.dataLoaderService.getFieldValues(entityName, filterField.name).then((data) => {
                var temp = [...data.instances];
                temp.push('All');
                setFilterValues(temp);
            });
        }
    }, [filterField]);

    useEffect(() => {
        const dataSub = serviceFactoryInstance.dataLoaderService
            .dataSub(
                entityName,
                tenant,
                noOfInstances,
                startOfInstances,
                queryString,
                fields,
                sortField,
                sortDirection,
                filterField && filterValue !== 'All' ? filterField.name : undefined,
                filterValue && filterValue !== 'All' && !presetFilterValue ? filterValue : presetFilterValue ? presetFilterValue : undefined
            )
            .subscribe((data) => {
                if (data) {
                    setData(data);
                }
            });

        return () => {
            dataSub.unsubscribe();
        };
    }, [serviceFactoryInstance.cache, noOfInstances, startOfInstances, tenant, queryString, sortField, sortDirection, filterValue]);

    useEffect(() => {
        const dataCountSub = serviceFactoryInstance.dataLoaderService.countSub(entityName).subscribe((data) => {
            if (data) {
                setCount(data);
            } else {
                setCount(0);
            }
        });

        return () => {
            dataCountSub.unsubscribe();
        };
    }, [serviceFactoryInstance.cache, tenant]);

    const handleDeleteOK = () => {
        deleteData(deleteUUIDS);
        setConfirmDeleteForm(false);
    };

    const handleDeleteCancel = () => {
        setConfirmDeleteForm(false);
    };

    const [anchorEl, setAnchorEl] = useState(null);

    const handleClick = (event) => {
        setAnchorEl(event.currentTarget);
    };

    const handleClose = () => {
        setAnchorEl(null);
    };

    const open = Boolean(anchorEl);
    const id = open ? 'simple-popover' : undefined;

    const CustomToolbar = () => {
        return (
            <Box>
                {filterField && !presetFilterValue && (
                    <>
                        <ButtonBase
                            sx={{
                                p: 0.25,
                                bgcolor: 'secondary.lighter',
                                borderRadius: 1,
                                '&:hover': { bgcolor: 'secondary.light' }
                            }}
                            onClick={handleClick}
                        >
                            <Stack direction="row" spacing={2} alignItems="center" sx={{ p: 0.5 }}>
                                <Typography>Select {filterField.label}</Typography>
                                <FilterFilled />
                            </Stack>
                        </ButtonBase>
                        <Popover
                            id={id}
                            open={open}
                            anchorEl={anchorEl}
                            onClose={handleClose}
                            anchorOrigin={{
                                vertical: 'bottom',
                                horizontal: 'left'
                            }}
                        >
                            <Paper
                                sx={{
                                    width: 290,
                                    minWidth: 240,
                                    maxWidth: 290
                                }}
                            >
                                <>
                                    <List component="nav">
                                        {filterValues && (
                                            <>
                                                {filterValues.map((value) => {
                                                    return (
                                                        <ListItemButton
                                                            key={value}
                                                            onClick={() => {
                                                                setFilterValue(value);
                                                                handleClose();
                                                            }}
                                                        >
                                                            <ListItemText primary={value} />
                                                        </ListItemButton>
                                                    );
                                                })}
                                            </>
                                        )}
                                    </List>
                                </>
                            </Paper>
                        </Popover>
                    </>
                )}
            </Box>
        );
    };

    const options = {
        customToolbar: CustomToolbar,
        onRowsDelete: (rowsDeleted, dataRows) => {
            const rowsDeleteUUIDS = [];
            for (let i = 0; i < rowsDeleted.data.length; i++) {
                rowsDeleteUUIDS.push(data[rowsDeleted.data[i].dataIndex].UUID);
            }
            setDeleteUUIDS(rowsDeleteUUIDS);
            setConfirmDeleteForm(true);
        },
        onRowClick: (rowData, rowMeta) => {
            if (openForm && setUUID) {
                setUUID(data[rowMeta.dataIndex].UUID);
                openForm();
            }
            if (navigateToPage) {
                navigateToPage(data[rowMeta.dataIndex].UUID);
            }
        },
        selectableRowsHideCheckboxes: deleteData ? false : true,
        count: count,
        rowsPerPage: noOfInstances,
        rowsPerPageOptions: [10, 25, 50],
        serverSide: true,
        page: page,
        filter: filter ? filter : false,
        onChangePage(currentPage) {
            setPage(currentPage);
            setStartOfInstances(currentPage * noOfInstances);
        },
        onChangeRowsPerPage(numberOfRows) {
            setPage(0);
            setStartOfInstances(0);
            setNoOfInstances(numberOfRows);
        },
        filter: false,
        onDownload: (buildHead, buildBody, columns, data) => {
            const findBy = tenant ? '["tenant_id"]' : undefined;
            const value = tenant ? `["${tenant.UUID}"]` : undefined;
            const direction = tenant ? '["0"]' : undefined;
            serviceFactoryInstance.dataLoaderService
                .getFilteredAndSortedInstances(entityName, queryString, fields, sortField, sortDirection, findBy, value, direction, false)
                .then((data) => {
                    setDownloadData(data.instances);
                    const link = document.getElementById('download-link');
                    link.click();
                });
            return false;
        },
        onTableChange: (action, tableState) => {
            switch (action) {
                case 'search':
                    setQueryString(tableState.searchText);
                    break;
                case 'sort':
                    if (tableState.sortOrder.direction === 'asc') {
                        setSortField(tableState.sortOrder.name);
                        setSortDirection(1);
                    } else if (tableState.sortOrder.direction === 'desc') {
                        setSortField(tableState.sortOrder.name);
                        setSortDirection(-1);
                    }
                    break;
                default:
                    console.log('action not handled.');
            }
        }
    };

    return (
        <>
            <ConfirmationDialog
                open={confirmDeleteForm}
                title="Delete Confirmation"
                message={
                    (deleteUUIDS.length > 1 && `Are you sure you want to delete the ${configs.multiple}?`) ||
                    (deleteUUIDS.length === 1 && `Are you sure you want to delete the ${configs.single}?`)
                }
                onOK={handleDeleteOK}
                onCancel={handleDeleteCancel}
            />

            <CSVLink data={downloadData} headers={downloadConfigs} id="download-link" />
            <MUIDataTable options={options} data={data} columns={configs.fields} title={summary && <Summary summary={summary}></Summary>} />
        </>
    );
};

export default CustomDatatable;
