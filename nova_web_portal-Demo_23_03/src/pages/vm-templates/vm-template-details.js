import { useEffect, useState } from 'react';
import { useParams } from 'react-router-dom';
import { useNavigate } from '../../../node_modules/react-router/index';
import serviceFactoryInstance from 'framework/services/service-factory';
import { ENTITY_NAME_VM_CONFIGS, ENTITY_NAME_VM_TEMPLATES } from 'framework/caching/entity-cache';
import * as Yup from 'yup';
import { Formik } from 'formik';
import AnimateButton from 'components/@extended/AnimateButton';
// material-ui
import { Button, FormHelperText, Grid, InputLabel, OutlinedInput, Stack, Typography } from '@mui/material';
import configs from './vm-configs-config.json';
import CustomSnackbar from 'components/styledMUI/Snackbar';
import VMConfigsForm from './vm-configs-form';
import DeviceSelectForm from './device-select-form';
import CustomDatatable from 'components/styledMUI/Datatable';

const DetailsPage = ({ title }) => {
    const params = useParams();
    const [vmTemplate, setVmTemplate] = useState();
    const [initialValues, setInitialValues] = useState({
        instance_name: ''
    });
    const [UUID, setUUID] = useState();
    const [formOpen, setFormOpen] = useState(false);
    const [formDevicesOpen, setFormDevicesOpen] = useState(false);
    const [errorSnackbarMessage, setErrorSnackbarMessage] = useState('');
    const [successSnackbarMessage, setSuccessSnackbarMessage] = useState('');
    const navigate = useNavigate();

    useEffect(() => {
        document.title = title;
    }, []);

    useEffect(() => {
        if (params.UUID) {
            serviceFactoryInstance.dataLoaderService.getInstance(params.UUID, ENTITY_NAME_VM_TEMPLATES).then((data) => {
                if (data.status) {
                    console.log(data.instance);
                    setVmTemplate(data.instance);
                    const temp = {};
                    temp.instance_name = data.instance.instance_name;
                    temp.UUID = data.instance.UUID;
                    setInitialValues(temp);
                }
            });
        }
    }, [params.UUID, serviceFactoryInstance.cache]);

    const closeForm = () => {
        setUUID();
        setFormOpen(false);
    };

    const openForm = () => {
        setFormOpen(true);
    };

    const cleanCloseForm = () => {
        setInitialValues({
            instance_name: vmTemplate && vmTemplate.instance_name ? vmTemplate.instance_name : ''
        });
    };

    const closeDevicesForm = () => {
        setFormDevicesOpen(false);
    };

    const openDevicesForm = () => {
        setFormDevicesOpen(true);
    };

    const deleteData = (rows) => {
        for (let i = 0; i < rows.length; i++) {
            const UUID = rows[i];
            serviceFactoryInstance.dataLoaderService
                .deleteInstance(ENTITY_NAME_VM_CONFIGS, UUID)
                .then((data) => {
                    if (data.status) {
                        setSuccessSnackbarMessage('Delete configs successful');
                    } else {
                        setErrorSnackbarMessage('Delete configs failed');
                    }
                })
                .catch((reason) => {
                    setErrorSnackbarMessage('Delete configs failed');
                });
        }
    };

    return (
        <>
            <CustomSnackbar msg={successSnackbarMessage} onClose={() => setSuccessSnackbarMessage('')} severity="success" title="Success" />
            <CustomSnackbar msg={errorSnackbarMessage} onClose={() => setErrorSnackbarMessage('')} severity="error" title="Error" />

            <Grid container>
                <Grid item xs={9}>
                    <Typography variant="h4">{vmTemplate ? `Details of ${vmTemplate.instance_name}` : 'New template'}</Typography>
                </Grid>
                {params.UUID && vmTemplate && (
                    <Grid item xs={3}>
                        <DeviceSelectForm
                            formOpen={formDevicesOpen}
                            closeForm={closeDevicesForm}
                            setSuccessSnackbarMessage={(msg) => setSuccessSnackbarMessage(msg)}
                            setErrorSnackbarMessage={(msg) => setErrorSnackbarMessage(msg)}
                            vmTemplate={params.UUID}
                        />
                        <AnimateButton>
                            <Button
                                onClick={() => openDevicesForm()}
                                disableElevation
                                fullWidth
                                size="large"
                                variant="contained"
                                color="primary"
                                type="button"
                            >
                                Apply Template
                            </Button>
                        </AnimateButton>
                    </Grid>
                )}
            </Grid>
            <Grid container>
                <Grid item xs={12}>
                    <Formik
                        enableReinitialize
                        initialValues={initialValues}
                        validationSchema={Yup.object().shape({
                            instance_name: Yup.string().required('Template name is required')
                        })}
                        onSubmit={async (values, { setErrors, setSubmitting }) => {
                            setSubmitting(true);
                            console.log(values);
                            params.UUID
                                ? serviceFactoryInstance.dataLoaderService
                                      .updateInstance(ENTITY_NAME_VM_TEMPLATES, values)
                                      .then((data) => {
                                          if (data.status) {
                                              setSubmitting(false);
                                              setSuccessSnackbarMessage('Edit template successful');
                                              navigate(`/vmtemplates/details/${params.UUID}`);
                                          } else {
                                              setErrors({ submit: data.reason });
                                              setSubmitting(false);
                                              cleanCloseForm();
                                              setErrorSnackbarMessage('Edit template failed');
                                          }
                                      })
                                      .catch((reason) => {
                                          setErrors({ submit: reason });
                                          setSubmitting(false);
                                          setErrorSnackbarMessage('Edit template failed');
                                      })
                                : serviceFactoryInstance.dataLoaderService
                                      .addInstance(ENTITY_NAME_VM_TEMPLATES, values)
                                      .then((data) => {
                                          if (data.status) {
                                              setSubmitting(false);
                                              setSuccessSnackbarMessage('Successfully added template');
                                              navigate(`/vmtemplates/details/${data.UUID}`);
                                          } else {
                                              setErrors({ submit: data.reason });
                                              setSubmitting(false);
                                              setErrorSnackbarMessage('Add template failed');
                                          }
                                      })
                                      .catch((reason) => {
                                          setErrors({ submit: reason });
                                          setSubmitting(false);
                                          setErrorSnackbarMessage('Add template failed');
                                      });
                        }}
                    >
                        {({ errors, handleBlur, handleChange, handleSubmit, isSubmitting, touched, values, resetForm }) => (
                            <form noValidate onSubmit={handleSubmit}>
                                <Grid container spacing={3}>
                                    <Grid item xs={12}>
                                        <Stack spacing={1}>
                                            <InputLabel htmlFor="vm-template-form-instance-name">Template Name</InputLabel>
                                            <OutlinedInput
                                                id="vm-template-form-instance_name"
                                                type="text"
                                                value={values.instance_name}
                                                name="instance_name"
                                                onBlur={handleBlur}
                                                onChange={handleChange}
                                                placeholder="Enter template name"
                                                fullWidth
                                                error={Boolean(touched.instance_name && errors.instance_name)}
                                            />
                                            {touched.instance_name && errors.instance_name && (
                                                <FormHelperText error id="standard-weight-helper-text-vm-template-form-instance_name">
                                                    {errors.instance_name}
                                                </FormHelperText>
                                            )}
                                        </Stack>
                                    </Grid>
                                    {errors.submit && (
                                        <Grid item xs={12}>
                                            <FormHelperText error>{errors.submit}</FormHelperText>
                                        </Grid>
                                    )}
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
                                                {!params.UUID ? 'Save new template' : 'Save changes'}
                                            </Button>
                                        </AnimateButton>
                                    </Grid>
                                    <Grid item xs={12} md={6}>
                                        <AnimateButton>
                                            <Button
                                                onClick={() => resetForm()}
                                                disableElevation
                                                fullWidth
                                                size="large"
                                                variant="contained"
                                                color="primary"
                                                type="button"
                                            >
                                                Cancel changes
                                            </Button>
                                        </AnimateButton>
                                    </Grid>
                                </Grid>
                            </form>
                        )}
                    </Formik>
                </Grid>
            </Grid>
            <br />
            <Grid item xs={12}>
                <Stack spacing={1} style={{ padding: 20 }}>
                    {params.UUID && (
                        <>
                            <Typography variant="h5">VNF configs saved under this template</Typography>
                            <CustomDatatable
                                entityName={ENTITY_NAME_VM_CONFIGS}
                                configs={configs}
                                deleteData={deleteData}
                                setUUID={setUUID}
                                openForm={openForm}
                                presetFilterValue={params.UUID}
                            />
                            <VMConfigsForm
                                formOpen={formOpen}
                                closeForm={closeForm}
                                UUID={UUID}
                                setSuccessSnackbarMessage={(msg) => setSuccessSnackbarMessage(msg)}
                                setErrorSnackbarMessage={(msg) => setErrorSnackbarMessage(msg)}
                                vmTemplate={params.UUID}
                            />
                            <Grid item xs={12} md={6}>
                                <AnimateButton>
                                    <Button
                                        onClick={() => openForm()}
                                        disableElevation
                                        fullWidth
                                        size="large"
                                        variant="contained"
                                        color="primary"
                                        type="button"
                                    >
                                        Add Config
                                    </Button>
                                </AnimateButton>
                            </Grid>
                        </>
                    )}
                </Stack>
            </Grid>
        </>
    );
};

export default DetailsPage;
