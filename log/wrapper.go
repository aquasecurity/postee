package log

type Wrapper struct {
	logger LoggerType
}

func NewWrapper(logger LoggerType) LoggerType {
	return &Wrapper{logger}
}

func prepandPosteeSuffix(args ...interface{}) []interface{} {
	if len(args) == 0 {
		return args
	}
	return append([]interface{}{"[Postee] "}, args...)
}

func (r *Wrapper) Info(args ...interface{}) {
	r.logger.Info(prepandPosteeSuffix(args)...)
}

func (r *Wrapper) Infof(template string, args ...interface{}) {
	r.logger.Infof("[Postee] "+template, args...)
}

func (r *Wrapper) Error(args ...interface{}) {
	r.logger.Error(prepandPosteeSuffix(args)...)
}

func (r *Wrapper) Errorf(template string, args ...interface{}) {
	r.logger.Errorf("[Postee] "+template, args...)
}

func (r *Wrapper) Warn(args ...interface{}) {
	r.logger.Warn(prepandPosteeSuffix(args)...)
}

func (r *Wrapper) Warnf(template string, args ...interface{}) {
	r.logger.Warnf("[Postee] "+template, args...)
}

func (r *Wrapper) Debug(args ...interface{}) {
	r.logger.Debug(prepandPosteeSuffix(args)...)
}

func (r *Wrapper) Debugf(template string, args ...interface{}) {
	r.logger.Debugf("[Postee] "+template, args...)
}

func (r *Wrapper) Fatal(args ...interface{}) {
	r.logger.Fatal(prepandPosteeSuffix(args)...)
}

func (r *Wrapper) Fatalf(template string, args ...interface{}) {
	r.logger.Fatalf("[Postee] "+template, args...)
}
