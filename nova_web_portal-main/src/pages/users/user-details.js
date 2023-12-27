import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useParams } from 'react-router-dom';
import serviceFactoryInstance from 'framework/services/service-factory';
import { EyeOutlined, EyeInvisibleOutlined } from '@ant-design/icons';
import { ENTITY_NAME_COMPANY, ENTITY_NAME_USERS } from 'framework/caching/entity-cache';
// material-ui
import {
    Card,
    CardContent,
    Checkbox,
    Button,
    FormHelperText,
    Grid,
    IconButton,
    InputAdornment,
    InputLabel,
    OutlinedInput,
    Stack,
    FormControlLabel,
    FormGroup
} from '@mui/material';
// third party
import { Formik } from 'formik';
// project import
import AnimateButton from 'components/@extended/AnimateButton';
import CustomSnackbar from 'components/styledMUI/Snackbar';
import { Select, MenuItem } from '../../../node_modules/@mui/material/index';
import Multiselect from '../../../node_modules/multiselect-react-dropdown/dist/index';

// ============================|| FIREBASE - LOGIN ||============================ //

const DetailsPage = ({ title }) => {
    const [initialValues, setInitialValues] = useState({
        instance_name: '',
        email: '',
        first_name: '',
        last_name: '',
        old_pwd: '',
        new_pwd: '',
        new_pwd_re: '',
        company: ''
    });

    const params = useParams();
    const [edit, setEdit] = useState(true);
    const [showOldPwd, setShowOldPwd] = useState(false);
    const [showNewPwd, setShowNewPwd] = useState(false);
    const [showNewPwdRe, setShowNewPwdRe] = useState(false);
    const [changePwd, setChangePwd] = useState(false);
    const navigate = useNavigate();
    const [errorSnackbarMessage, setErrorSnackbarMessage] = useState('');
    const [successSnackbarMessage, setSuccessSnackbarMessage] = useState('');
    const [companies, setCompanies] = useState([]);
    const [selectedCompany, setSelectedCompany] = useState();
    const [selectedTenants, setSelectedTenants] = useState([]);
    const [tenants, setTenants] = useState([]);

    useEffect(() => {
        document.title = title;
    }, []);

    useEffect(() => {
        if (selectedCompany) {
            setTenants(selectedCompany.tenants);
        }
    }, [selectedCompany]);

    useEffect(() => {
        const companiesSub = serviceFactoryInstance.dataLoaderService.dataSub(`${ENTITY_NAME_COMPANY}>summary`).subscribe((data) => {
            if (data) {
                setCompanies(data);
            }
        });
        return () => {
            companiesSub.unsubscribe();
        };
    }, [serviceFactoryInstance.cache]);

    useEffect(() => {
        if (params.UUID !== undefined) {
            //edit an existing instance
            serviceFactoryInstance.dataLoaderService.getInstance(params.UUID, ENTITY_NAME_USERS).then((data) => {
                if (data.status) {
                    var temp = {};
                    temp['UUID'] = data.instance.UUID;
                    temp['instance_name'] = data.instance.instance_name;
                    temp['email'] = data.instance.email;
                    temp['first_name'] = data.instance.first_name;
                    temp['last_name'] = data.instance.last_name;
                    temp['company'] = data.instance.company;
                    temp['old_pwd'] = '';
                    temp['new_pwd'] = '';
                    temp['new_pwd_re'] = '';
                    setInitialValues(temp);
                    setSelectedTenants(data.instance.tenants ? data.instance.tenants : []);
                    getTenants(data.instance.company);
                }
            });
        } else {
            setEdit(true);
        }
    }, [params.UUID]);

    const getTenants = (UUID) => {
        serviceFactoryInstance.dataLoaderService.getInstance(UUID, ENTITY_NAME_COMPANY).then((data) => {
            if (data.status) {
                setTenants(data.instance && data.instance.tenants ? data.instance.tenants : []);
            }
        });
    };

    const onSelect = (selectedList, selectedItem) => {
        setSelectedTenants([...selectedList]);
    };

    const onRemove = (selectedList, removedItem) => {
        var selectedListTemp = [...selectedList];
        const position = selectedList.indexOf(removedItem);
        if (position !== -1) {
            selectedListTemp.splice(position, 1);
        }
        setSelectedTenants(selectedListTemp);
    };

    const editSet = () => {
        setEdit(true);
    };

    const editUnset = () => {
        setEdit(false);
    };

    return (
        <>
            <CustomSnackbar msg={successSnackbarMessage} onClose={() => setSuccessSnackbarMessage('')} severity="success" title="Success" />
            <CustomSnackbar msg={errorSnackbarMessage} onClose={() => setErrorSnackbarMessage('')} severity="error" title="Error" />
            <Card>
                <CardContent>
                    <Formik
                        enableReinitialize
                        initialValues={initialValues}
                        onSubmit={async (values, { setErrors, setSubmitting }) => {
                            setSubmitting(true);
                            var pass = true;
                            var temp = {};
                            temp['instance_name'] = values.instance_name;
                            temp['email'] = values.email;
                            temp['first_name'] = values.first_name;
                            temp['last_name'] = values.last_name;
                            temp['company'] = values.company;
                            temp['tenants'] = selectedTenants;

                            if (params.UUID && changePwd) {
                                if (values.new_pwd !== values.new_pwd_re) {
                                    setErrors({ new_pwd_re: 'Passwords should match' });
                                    pass = false;
                                    setSubmitting(false);
                                } else {
                                    temp['old_pwd'] = values.old_pwd;
                                    temp['new_pwd'] = values.new_pwd;
                                }
                            }
                            if (!params.UUID) {
                                temp['pwd'] = values.new_pwd;
                            }
                            if (pass) {
                                console.log(params.UUID);
                                params.UUID
                                    ? serviceFactoryInstance.authService
                                          .updateUser({ ...temp, UUID: params.UUID })
                                          .then((data) => {
                                              if (data.status) {
                                                  setSubmitting(false);
                                                  setSuccessSnackbarMessage('Successfully edited the user');
                                              } else {
                                                  setErrors({ submit: data.reason });
                                                  setSubmitting(false);
                                                  setErrorSnackbarMessage('User update failed');
                                              }
                                          })
                                          .catch((reason) => {
                                              setErrors({ submit: reason });
                                              setSubmitting(false);
                                          })
                                    : serviceFactoryInstance.authService
                                          .addUser(temp)
                                          .then((data) => {
                                              if (data.status) {
                                                  setSubmitting(false);
                                                  setSuccessSnackbarMessage('Successfully added the user');
                                              } else {
                                                  setErrors({ submit: data.reason });
                                                  setSubmitting(false);
                                                  setErrorSnackbarMessage('User update failed');
                                              }
                                          })
                                          .catch((reason) => {
                                              setErrors({ submit: reason });
                                              setSubmitting(false);
                                              setErrorSnackbarMessage('User update failed');
                                          });
                            }
                        }}
                    >
                        {({ errors, handleBlur, handleChange, handleSubmit, isSubmitting, touched, values, resetForm }) => (
                            <form noValidate onSubmit={handleSubmit}>
                                <Grid container spacing={3}>
                                    <Grid item xs={12}>
                                        <Stack spacing={1}>
                                            <InputLabel htmlFor="user-form-instance_name">User Name</InputLabel>
                                            <OutlinedInput
                                                id="user-form-instance_name"
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
                                                <FormHelperText error id="standard-weight-helper-text-user-form-instance_name">
                                                    {errors.instance_name}
                                                </FormHelperText>
                                            )}
                                        </Stack>
                                    </Grid>
                                    <Grid item xs={12}>
                                        <Stack spacing={1}>
                                            <InputLabel htmlFor="user-form-email">Email</InputLabel>
                                            <OutlinedInput
                                                id="user-form-email"
                                                type="text"
                                                value={values.email}
                                                disabled={!edit}
                                                name="email"
                                                onBlur={handleBlur}
                                                onChange={handleChange}
                                                placeholder="Enter email"
                                                fullWidth
                                                error={Boolean(touched.email && errors.email)}
                                            />
                                            {touched.email && errors.email && (
                                                <FormHelperText error id="standard-weight-helper-text-user-form-email">
                                                    {errors.email}
                                                </FormHelperText>
                                            )}
                                        </Stack>
                                    </Grid>
                                    <Grid item xs={12}>
                                        <Stack spacing={1}>
                                            <InputLabel htmlFor="user-form-first_name">First Name</InputLabel>
                                            <OutlinedInput
                                                id="user-form-first_name"
                                                type="text"
                                                value={values.first_name}
                                                disabled={!edit}
                                                name="first_name"
                                                onBlur={handleBlur}
                                                onChange={handleChange}
                                                placeholder="Enter first name"
                                                fullWidth
                                                error={Boolean(touched.first_name && errors.first_name)}
                                            />
                                            {touched.first_name && errors.first_name && (
                                                <FormHelperText error id="standard-weight-helper-text-user-form-first_name">
                                                    {errors.first_name}
                                                </FormHelperText>
                                            )}
                                        </Stack>
                                    </Grid>
                                    <Grid item xs={12}>
                                        <Stack spacing={1}>
                                            <InputLabel htmlFor="user-form-last_name">Last Name</InputLabel>
                                            <OutlinedInput
                                                id="user-form-last_name"
                                                type="text"
                                                value={values.last_name}
                                                disabled={!edit}
                                                name="last_name"
                                                onBlur={handleBlur}
                                                onChange={handleChange}
                                                placeholder="Enter last name"
                                                fullWidth
                                                error={Boolean(touched.last_name && errors.last_name)}
                                            />
                                            {touched.last_name && errors.last_name && (
                                                <FormHelperText error id="standard-weight-helper-text-user-form-last_name">
                                                    {errors.last_name}
                                                </FormHelperText>
                                            )}
                                        </Stack>
                                    </Grid>
                                    {companies && (
                                        <Grid item xs={12}>
                                            <Stack spacing={1}>
                                                <InputLabel htmlFor="user-form-company">Company</InputLabel>
                                                <Select
                                                    id="user-form-company"
                                                    type="text"
                                                    value={values.company}
                                                    name="company"
                                                    onBlur={handleBlur}
                                                    onChange={(e) => {
                                                        handleChange(e);
                                                        getTenants(e.target.value);
                                                    }}
                                                    placeholder="Select company"
                                                    fullWidth
                                                    error={Boolean(touched.company && errors.company)}
                                                >
                                                    {companies
                                                        ? companies.map(
                                                              (company) =>
                                                                  company && (
                                                                      <MenuItem key={company.UUID} value={company.UUID}>
                                                                          {company.instance_name}
                                                                      </MenuItem>
                                                                  )
                                                          )
                                                        : ''}
                                                </Select>
                                                {touched.company && errors.company && (
                                                    <FormHelperText error id="standard-weight-helper-text-user-form-company">
                                                        {errors.company}
                                                    </FormHelperText>
                                                )}
                                            </Stack>
                                        </Grid>
                                    )}
                                    {tenants && (
                                        <Grid item xs={12}>
                                            <Stack spacing={1} style={{ height: 150 }}>
                                                <InputLabel htmlFor="user-form-tenants">Select tenants</InputLabel>
                                                <Multiselect
                                                    showCheckbox={true}
                                                    options={tenants} // Options to display in the dropdown
                                                    selectedValues={selectedTenants} // Preselected value to persist in dropdown
                                                    onSelect={onSelect} // Function will trigger on select event
                                                    onRemove={onRemove} // Function will trigger on remove event
                                                    displayValue="instance_name" // Property name to display in the dropdown options
                                                />
                                                {touched.tenants && errors.tenants && (
                                                    <FormHelperText error id="standard-weight-helper-text-user-form-tenants">
                                                        {errors.tenants}
                                                    </FormHelperText>
                                                )}
                                            </Stack>
                                        </Grid>
                                    )}

                                    {params.UUID && (
                                        <Grid item xs={12}>
                                            <Stack spacing={1}>
                                                <FormGroup>
                                                    <FormControlLabel
                                                        control={
                                                            <Checkbox
                                                                checked={changePwd}
                                                                onChange={() => {
                                                                    if (changePwd) {
                                                                        values.old_pwd = '';
                                                                        values.new_pwd = '';
                                                                        values.new_pwd_re = '';
                                                                    }
                                                                    setChangePwd(!changePwd);
                                                                }}
                                                            />
                                                        }
                                                        label="Change password"
                                                    />
                                                </FormGroup>
                                                {changePwd && (
                                                    <>
                                                        <Grid item xs={12}>
                                                            <Stack spacing={1}>
                                                                <InputLabel htmlFor="user-form-old-pwd">Old Password</InputLabel>
                                                                <OutlinedInput
                                                                    id="user-form-old-pwd"
                                                                    type={showOldPwd ? 'text' : 'password'}
                                                                    value={values.old_pwd}
                                                                    disabled={!edit}
                                                                    name="old_pwd"
                                                                    onBlur={handleBlur}
                                                                    onChange={handleChange}
                                                                    placeholder="Enter old password"
                                                                    fullWidth
                                                                    error={Boolean(touched.old_pwd && errors.old_pwd)}
                                                                    endAdornment={
                                                                        <InputAdornment position="end">
                                                                            <IconButton
                                                                                aria-label="toggle password visibility"
                                                                                onClick={() => setShowOldPwd(!showOldPwd)}
                                                                            >
                                                                                {showOldPwd ? <EyeOutlined /> : <EyeInvisibleOutlined />}
                                                                            </IconButton>
                                                                        </InputAdornment>
                                                                    }
                                                                />
                                                                {touched.old_pwd && errors.old_pwd && (
                                                                    <FormHelperText
                                                                        error
                                                                        id="standard-weight-helper-text-user-form-old-pwd"
                                                                    >
                                                                        {errors.old_pwd}
                                                                    </FormHelperText>
                                                                )}
                                                            </Stack>
                                                        </Grid>
                                                        <Grid item xs={12}>
                                                            <Stack spacing={1}>
                                                                <InputLabel htmlFor="user-form-new-pwd">New Password</InputLabel>
                                                                <OutlinedInput
                                                                    id="user-form-new-pwd"
                                                                    type={showNewPwd ? 'text' : 'password'}
                                                                    value={values.new_pwd}
                                                                    disabled={!edit}
                                                                    name="new_pwd"
                                                                    onBlur={handleBlur}
                                                                    onChange={handleChange}
                                                                    placeholder="Enter new password"
                                                                    fullWidth
                                                                    error={Boolean(touched.new_pwd && errors.new_pwd)}
                                                                    endAdornment={
                                                                        <InputAdornment position="end">
                                                                            <IconButton
                                                                                aria-label="toggle password visibility"
                                                                                onClick={() => setShowNewPwd(!showNewPwd)}
                                                                            >
                                                                                {showNewPwd ? <EyeOutlined /> : <EyeInvisibleOutlined />}
                                                                            </IconButton>
                                                                        </InputAdornment>
                                                                    }
                                                                />
                                                                {touched.new_pwd && errors.new_pwd && (
                                                                    <FormHelperText
                                                                        error
                                                                        id="standard-weight-helper-text-user-form-new-pwd"
                                                                    >
                                                                        {errors.new_pwd}
                                                                    </FormHelperText>
                                                                )}
                                                            </Stack>
                                                        </Grid>
                                                        <Grid item xs={12}>
                                                            <Stack spacing={1}>
                                                                <InputLabel htmlFor="user-form-new-pwd-re">
                                                                    Re-enter New Password
                                                                </InputLabel>
                                                                <OutlinedInput
                                                                    id="user-form-new-pwd-re"
                                                                    type={showNewPwdRe ? 'text' : 'password'}
                                                                    value={values.new_pwd_re}
                                                                    disabled={!edit}
                                                                    name="new_pwd_re"
                                                                    onBlur={handleBlur}
                                                                    onChange={handleChange}
                                                                    placeholder="Enter new password"
                                                                    fullWidth
                                                                    error={Boolean(touched.new_pwd_re && errors.new_pwd_re)}
                                                                    endAdornment={
                                                                        <InputAdornment position="end">
                                                                            <IconButton
                                                                                aria-label="toggle password visibility"
                                                                                onClick={() => setShowNewPwdRe(!showNewPwdRe)}
                                                                            >
                                                                                {showNewPwdRe ? <EyeOutlined /> : <EyeInvisibleOutlined />}
                                                                            </IconButton>
                                                                        </InputAdornment>
                                                                    }
                                                                />
                                                                {touched.new_pwd_re && errors.new_pwd_re && (
                                                                    <FormHelperText
                                                                        error
                                                                        id="standard-weight-helper-text-user-form-new-pwd-re"
                                                                    >
                                                                        {errors.new_pwd_re}
                                                                    </FormHelperText>
                                                                )}
                                                            </Stack>
                                                        </Grid>
                                                    </>
                                                )}
                                            </Stack>
                                        </Grid>
                                    )}

                                    {!params.UUID && (
                                        <Grid item xs={12}>
                                            <Stack spacing={1}>
                                                <Grid item xs={12}>
                                                    <Stack spacing={1}>
                                                        <InputLabel htmlFor="user-form-new-pwd">Password</InputLabel>
                                                        <OutlinedInput
                                                            id="user-form-new-pwd"
                                                            type={showNewPwd ? 'text' : 'password'}
                                                            value={values.new_pwd}
                                                            disabled={!edit}
                                                            name="new_pwd"
                                                            onBlur={handleBlur}
                                                            onChange={handleChange}
                                                            placeholder="Enter new password"
                                                            fullWidth
                                                            error={Boolean(touched.new_pwd && errors.new_pwd)}
                                                            endAdornment={
                                                                <InputAdornment position="end">
                                                                    <IconButton
                                                                        aria-label="toggle password visibility"
                                                                        onClick={() => setShowNewPwd(!showNewPwd)}
                                                                    >
                                                                        {showNewPwd ? <EyeOutlined /> : <EyeInvisibleOutlined />}
                                                                    </IconButton>
                                                                </InputAdornment>
                                                            }
                                                        />
                                                        {touched.new_pwd && errors.new_pwd && (
                                                            <FormHelperText error id="standard-weight-helper-text-user-form-new-pwd">
                                                                {errors.new_pwd}
                                                            </FormHelperText>
                                                        )}
                                                    </Stack>
                                                </Grid>
                                                <Grid item xs={12}>
                                                    <Stack spacing={1}>
                                                        <InputLabel htmlFor="user-form-new-pwd-re">Re-enter Password</InputLabel>
                                                        <OutlinedInput
                                                            id="user-form-new-pwd-re"
                                                            type={showNewPwdRe ? 'text' : 'password'}
                                                            value={values.new_pwd_re}
                                                            disabled={!edit}
                                                            name="new_pwd_re"
                                                            onBlur={handleBlur}
                                                            onChange={handleChange}
                                                            placeholder="Enter new password"
                                                            fullWidth
                                                            error={Boolean(touched.new_pwd_re && errors.new_pwd_re)}
                                                            endAdornment={
                                                                <InputAdornment position="end">
                                                                    <IconButton
                                                                        aria-label="toggle password visibility"
                                                                        onClick={() => setShowNewPwdRe(!showNewPwdRe)}
                                                                    >
                                                                        {showNewPwdRe ? <EyeOutlined /> : <EyeInvisibleOutlined />}
                                                                    </IconButton>
                                                                </InputAdornment>
                                                            }
                                                        />
                                                        {touched.new_pwd_re && errors.new_pwd_re && (
                                                            <FormHelperText error id="standard-weight-helper-text-user-form-new-pwd-re">
                                                                {errors.new_pwd_re}
                                                            </FormHelperText>
                                                        )}
                                                    </Stack>
                                                </Grid>
                                            </Stack>
                                        </Grid>
                                    )}
                                    {errors.submit && (
                                        <Grid item xs={12}>
                                            <FormHelperText error>{errors.submit}</FormHelperText>
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
                                                    navigate(`/users`);
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
