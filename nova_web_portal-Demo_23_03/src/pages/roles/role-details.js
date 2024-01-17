import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useParams } from 'react-router-dom';
import serviceFactoryInstance from 'framework/services/service-factory';
import { ENTITY_NAME_USER_ROLES, ENTITY_NAME_USER_PRIVILEGES } from 'framework/caching/entity-cache';
// material-ui
import { Card, CardContent, Button, FormHelperText, Grid, InputLabel, OutlinedInput, Stack } from '@mui/material';
// third party
import { Formik } from 'formik';
// project import
import AnimateButton from 'components/@extended/AnimateButton';
import CustomSnackbar from 'components/styledMUI/Snackbar';
import Multiselect from '../../../node_modules/multiselect-react-dropdown/dist/index';

// ============================|| FIREBASE - LOGIN ||============================ //

const DetailsPage = ({ title }) => {
    const [initialValues, setInitialValues] = useState({
        instance_name: ''
    });

    const params = useParams();
    const [edit, setEdit] = useState(true);
    const navigate = useNavigate();
    const [errorSnackbarMessage, setErrorSnackbarMessage] = useState('');
    const [successSnackbarMessage, setSuccessSnackbarMessage] = useState('');
    const [privileges, setPrivileges] = useState([]);
    const [selectedPrivileges, setSelectedPrivileges] = useState();

    useEffect(() => {
        document.title = title;
    }, []);

    useEffect(() => {
        const privilegesSub = serviceFactoryInstance.dataLoaderService.dataSub(ENTITY_NAME_USER_PRIVILEGES).subscribe((data) => {
            if (data) {
                setPrivileges(data);
            }
        });
        return () => {
            privilegesSub.unsubscribe();
        };
    }, [serviceFactoryInstance.cache]);

    useEffect(() => {
        if (params.UUID !== undefined && privileges.length > 0) {
            //edit an existing instance
            console.log(params.UUID);
            serviceFactoryInstance.dataLoaderService.getInstance(params.UUID, ENTITY_NAME_USER_ROLES).then((data) => {
                if (data.status) {
                    console.log(data);
                    var temp = {};
                    temp['UUID'] = data.instance.UUID;
                    temp['instance_name'] = data.instance.instance_name;
                    setInitialValues(temp);
                    if (data.instance.privileges) {
                        var tempPrivileges = [];
                        for (let i = 0; i < privileges.length; i++) {
                            if (data.instance.privileges.indexOf(privileges[i].UUID) > -1) {
                                tempPrivileges.push(privileges[i]);
                            }
                        }
                        setSelectedPrivileges(tempPrivileges);
                    }
                }
            });
        } else {
            setEdit(true);
        }
    }, [params.UUID, privileges]);

    const onSelect = (selectedList, selectedItem) => {
        setSelectedPrivileges([...selectedList]);
    };

    const onRemove = (selectedList, removedItem) => {
        var selectedListTemp = [...selectedList];
        const position = selectedList.indexOf(removedItem);
        if (position !== -1) {
            selectedListTemp.splice(position, 1);
        }
        setSelectedPrivileges(selectedListTemp);
    };

    return (
        <>
            <CustomSnackbar msg={successSnackbarMessage} onClose={() => setSuccessSnackbarMessage('')} severity="success" title="Success" />
            <CustomSnackbar msg={errorSnackbarMessage} onClose={() => setErrorSnackbarMessage('')} severity="error" title="Error" />
            <Card style={{ overflow: 'visible' }}>
                <CardContent>
                    <Formik
                        enableReinitialize
                        initialValues={initialValues}
                        onSubmit={async (values, { setErrors, setSubmitting }) => {
                            setSubmitting(true);
                            var tempPrivileges = [];
                            for (let i = 0; i < selectedPrivileges.length; i++) {
                                tempPrivileges.push(selectedPrivileges[i].UUID);
                            }
                            var temp = {};
                            temp['instance_name'] = values.instance_name;
                            temp['privileges'] = tempPrivileges;

                            params.UUID
                                ? serviceFactoryInstance.dataLoaderService
                                      .updateInstance(ENTITY_NAME_USER_ROLES, { ...temp, UUID: params.UUID })
                                      .then((data) => {
                                          if (data.status) {
                                              setSubmitting(false);
                                              setSuccessSnackbarMessage('Successfully edited the role');
                                          } else {
                                              setErrors({ submit: data.reason });
                                              setSubmitting(false);
                                              setErrorSnackbarMessage('Role update failed');
                                          }
                                      })
                                      .catch((reason) => {
                                          setErrors({ submit: reason });
                                          setSubmitting(false);
                                      })
                                : serviceFactoryInstance.dataLoaderService
                                      .addInstance(ENTITY_NAME_USER_ROLES, temp)
                                      .then((data) => {
                                          if (data.status) {
                                              setSubmitting(false);
                                              setSuccessSnackbarMessage('Successfully added the role');
                                          } else {
                                              setErrors({ submit: data.reason });
                                              setSubmitting(false);
                                              setErrorSnackbarMessage('Role add failed');
                                          }
                                      })
                                      .catch((reason) => {
                                          setErrors({ submit: reason });
                                          setSubmitting(false);
                                          setErrorSnackbarMessage('Role add failed');
                                      });
                        }}
                    >
                        {({ errors, handleBlur, handleChange, handleSubmit, isSubmitting, touched, values, resetForm }) => (
                            <form noValidate onSubmit={handleSubmit}>
                                <Grid container spacing={3}>
                                    <Grid item xs={12}>
                                        <Stack spacing={1}>
                                            <InputLabel htmlFor="role-form-instance_name">Role Name</InputLabel>
                                            <OutlinedInput
                                                id="role-form-instance_name"
                                                type="text"
                                                value={values.instance_name}
                                                disabled={!edit}
                                                name="instance_name"
                                                onBlur={handleBlur}
                                                onChange={handleChange}
                                                placeholder="Enter username"
                                                fullWidth
                                                error={Boolean(touched.instance_name && errors.instance_name)}
                                            />
                                            {touched.instance_name && errors.instance_name && (
                                                <FormHelperText error id="standard-weight-helper-text-role-form-instance_name">
                                                    {errors.instance_name}
                                                </FormHelperText>
                                            )}
                                        </Stack>
                                    </Grid>
                                    {privileges && (
                                        <Grid item xs={12}>
                                            <Stack spacing={1} style={{ height: 150 }}>
                                                <InputLabel htmlFor="role-form-tenants">Select privileges</InputLabel>
                                                <Multiselect
                                                    showCheckbox={true}
                                                    options={privileges} // Options to display in the dropdown
                                                    selectedValues={selectedPrivileges} // Preselected value to persist in dropdown
                                                    onSelect={onSelect} // Function will trigger on select event
                                                    onRemove={onRemove} // Function will trigger on remove event
                                                    displayValue="display_name" // Property name to display in the dropdown options
                                                />
                                                {touched.privileges && errors.privileges && (
                                                    <FormHelperText error id="standard-weight-helper-text-role-form-tenants">
                                                        {errors.privileges}
                                                    </FormHelperText>
                                                )}
                                            </Stack>
                                        </Grid>
                                    )}

                                    {params.UUID && (
                                        <Grid item xs={12} md={6}>
                                            <AnimateButton>
                                                <Button
                                                    disableElevation
                                                    disabled={isSubmitting}
                                                    fullWidth
                                                    size="large"
                                                    variant="contained"
                                                    color="primary"
                                                    type="submit"
                                                >
                                                    Save
                                                </Button>
                                            </AnimateButton>
                                        </Grid>
                                    )}
                                    {!params.UUID && (
                                        <>
                                            <Grid item xs={12} md={6}>
                                                <AnimateButton>
                                                    <Button
                                                        disableElevation
                                                        disabled={isSubmitting}
                                                        fullWidth
                                                        size="large"
                                                        type="submit"
                                                        variant="contained"
                                                        color="primary"
                                                    >
                                                        {!params.UUID ? 'Add' : 'Save'}
                                                    </Button>
                                                </AnimateButton>
                                            </Grid>
                                        </>
                                    )}
                                    <Grid item xs={12} md={6}>
                                        <AnimateButton>
                                            <Button
                                                onClick={() => {
                                                    resetForm();
                                                    /* editUnset(); */
                                                    /* if (!params.UUID) {
                                                                navigate(`/users`);
                                                            } */
                                                    navigate(`/roles`);
                                                }}
                                                disableElevation
                                                fullWidth
                                                size="large"
                                                variant="contained"
                                                color="primary"
                                                type="button"
                                            >
                                                Cancel
                                            </Button>
                                        </AnimateButton>
                                    </Grid>
                                </Grid>
                            </form>
                        )}
                    </Formik>
                </CardContent>
            </Card>
        </>
    );
};

export default DetailsPage;
